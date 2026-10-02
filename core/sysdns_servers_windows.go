//go:build windows

package fastime

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// systemDNSServers 只取「当前活跃网络」的 DNS 服务器：
// 先用 iphlpapi GetBestInterfaceEx 找到默认路由出口的网卡，
// 再只读该网卡注册表项下的 NameServer（静态）/ DhcpNameServer（DHCP 下发）。
// 这样 VPN 虚拟网卡、Hyper-V/WSL、已断开网卡的 DNS 不会混进来——
// 连 Wi-Fi 就是 Wi-Fi 的 DNS，插网线就是网线的 DNS。
// 活跃网卡识别失败时回退到旧行为（全部网卡合并）。
func systemDNSServers() []string {
	if guid := activeInterfaceGUID(); guid != "" {
		if out := dnsForInterface(guid); len(out) > 0 {
			return out
		}
	}
	return dnsAllInterfaces()
}

// activeInterfaceGUID 默认路由出口网卡的接口 GUID（注册表 Interfaces 下的键名，带花括号）。
// 链路：GetBestInterfaceEx(223.5.5.5) → ifIndex → ConvertInterfaceIndexToLuid
// → ConvertInterfaceLuidToGuid。全部走 iphlpapi，无需 cgo。
func activeInterfaceGUID() string {
	iphlp := windows.NewLazySystemDLL("iphlpapi.dll")
	getBest := iphlp.NewProc("GetBestInterfaceEx")
	idxToLuid := iphlp.NewProc("ConvertInterfaceIndexToLuid")
	luidToGuid := iphlp.NewProc("ConvertInterfaceLuidToGuid")

	// 手工构造 sockaddr_in（x/sys/windows 的 Sockaddr() 转换器未导出；
	// 内存布局与 sockaddr_in 一致即可，GetBestInterfaceEx 只看目标地址选路由）
	var sa windows.RawSockaddrInet4
	sa.Family = windows.AF_INET
	sa.Port = 53<<8 | 53>>8 // htons(53)
	copy(sa.Addr[:], net.ParseIP("223.5.5.5").To4())
	var ifIdx uint32
	if r, _, _ := getBest.Call(uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&ifIdx))); r != 0 {
		return ""
	}
	var luid uint64 // NET_LUID 为 64 位联合体
	if r, _, _ := idxToLuid.Call(uintptr(ifIdx), uintptr(unsafe.Pointer(&luid))); r != 0 {
		return ""
	}
	var g windows.GUID
	if r, _, _ := luidToGuid.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&g))); r != 0 {
		return ""
	}
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

// dnsForInterface 读指定接口 GUID 的 DNS（Tcpip + Tcpip6 两棵都查）。
func dnsForInterface(guid string) []string {
	var out []string
	seen := map[string]bool{}
	readKey := func(rootPath string) {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, rootPath+`\`+guid, registry.QUERY_VALUE)
		if err != nil {
			return
		}
		defer sk.Close()
		for _, val := range []string{"NameServer", "DhcpNameServer"} {
			if v, _, err := sk.GetStringValue(val); err == nil {
				addDNS(&out, seen, v)
			}
		}
	}
	readKey(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`)
	readKey(`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`)
	return out
}

// dnsAllInterfaces 回退：合并全部网卡的 DNS（无法识别活跃网卡时的旧行为）。
func dnsAllInterfaces() []string {
	var out []string
	seen := map[string]bool{}
	for _, rootPath := range []string{
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`,
	} {
		root, err := registry.OpenKey(registry.LOCAL_MACHINE, rootPath,
			registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, err := root.ReadSubKeyNames(-1)
		if err != nil {
			root.Close()
			continue
		}
		for _, name := range names {
			sk, err := registry.OpenKey(root, name, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			for _, val := range []string{"NameServer", "DhcpNameServer"} {
				if v, _, err := sk.GetStringValue(val); err == nil {
					addDNS(&out, seen, v)
				}
			}
			sk.Close()
		}
		root.Close()
	}
	return out
}

// addDNS 把逗号/空格分隔的 DNS 列表逐个校验加入（过滤 0.0.0.0 / :: 等无效地址）。
func addDNS(out *[]string, seen map[string]bool, v string) {
	for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		if !validDNSIP(s) || seen[s] {
			continue
		}
		seen[s] = true
		*out = append(*out, net.JoinHostPort(s, "53"))
	}
}
