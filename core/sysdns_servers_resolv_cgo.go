//go:build (ios || darwin) && cgo

package fastime

/*
#cgo LDFLAGS: -lresolv
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <resolv.h>

// fastime_sysdns 用 res_ninit + res_getservers 读取系统解析器当前生效的
// DNS 服务器列表（iOS/macOS 上这就是系统正在用的，含 Wi-Fi/蜂窝 DHCP 下发，
// 比 /etc/resolv.conf 更准确——macOS 的 resolv.conf 可能与实际配置不一致）。
// 返回空格分隔的 IP 字符串（调用方负责 free）；失败返回 NULL。
static char* fastime_sysdns() {
    struct __res_state st;
    memset(&st, 0, sizeof(st));
    if (res_ninit(&st) != 0) {
        return NULL;
    }
    union res_9_sockaddr_union addrs[16];
    int n = res_getservers(&st, addrs, 16);
    if (n <= 0) {
        res_ndestroy(&st);
        return NULL;
    }
    char* out = calloc(1, 16 * 64);
    if (!out) {
        res_ndestroy(&st);
        return NULL;
    }
    char ip[INET6_ADDRSTRLEN];
    for (int i = 0; i < n; i++) {
        const void* src = NULL;
        if (addrs[i].sin.sin_family == AF_INET) {
            src = &addrs[i].sin.sin_addr;
        } else if (addrs[i].sin6.sin_family == AF_INET6) {
            src = &addrs[i].sin6.sin6_addr;
        } else {
            continue;
        }
        if (inet_ntop(addrs[i].sin.sa_family, src, ip, sizeof(ip))) {
            if (strlen(out) > 0) strcat(out, " ");
            strcat(out, ip);
        }
    }
    res_ndestroy(&st);
    if (strlen(out) == 0) {
        free(out);
        return NULL;
    }
    return out;
}
*/
import "C"

import (
	"net"
	"strings"
	"unsafe"
)

// systemDNSServers iOS/macOS(cgo)：经 libresolv 读系统解析器实际生效的 DNS 列表。
func systemDNSServers() []string {
	cstr := C.fastime_sysdns()
	if cstr == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(cstr))
	var out []string
	seen := map[string]bool{}
	for _, s := range strings.Fields(C.GoString(cstr)) {
		if net.ParseIP(s) != nil && !seen[s] {
			seen[s] = true
			out = append(out, net.JoinHostPort(s, "53"))
		}
	}
	return out
}
