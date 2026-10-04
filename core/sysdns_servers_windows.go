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

// systemDNSServers 只取「当前真实物理网络」的 DNS 服务器：
// 枚举全部网卡，跳过虚拟网卡（VPN 客户端的 TAP/Wintun/WireGuard、VMware、
// Hyper-V 等——它们常强制接管全局流量，其 DNS 是虚拟/代理地址），
// 在物理网卡（以太网/Wi-Fi，有默认网关）里挑路由跃点最低的一张，
// 读它在注册表里的 NameServer（静态）/ DhcpNameServer（DHCP 下发）。
// 物理网卡识别失败时逐层回退：默认路由出口网卡 → 全部网卡合并（旧行为）。
func systemDNSServers() []string {
	if ifs := physicalInterfaces(); len(ifs) > 0 {
		if out := dnsForInterface(ifs[0].guid); len(out) > 0 {
			return out
		}
	}
	if guid := activeInterfaceGUID(); guid != "" {
		if out := dnsForInterface(guid); len(out) > 0 {
			return out
		}
	}
	return dnsAllInterfaces()
}

// winIface 一张物理网卡的关键信息（DNS 发现与 53 劫持接管共用）。
type winIface struct {
	guid    string   // 注册表 Interfaces 下的键名（带花括号）
	name    string   // 友好名（netsh 用，如 "WLAN"、"以太网"）
	metric  uint32   // IPv4 接口跃点（越小越优先）
	servers []string // 当前 DNS（NameServer 静态 + DhcpNameServer）
	dhcpDNS bool     // DNS 是否来自 DHCP（恢复时用 dhcp 方式还原）
}

// 虚拟网卡关键词：友好名/描述包含即跳过（不区分大小写）。
// 覆盖常见 VPN/代理/虚拟机/容器网卡，它们的 DNS 不是真实物理网络的。
var virtualIfKeywords = []string{
	"tap", "wintun", "wireguard", "vpn", "openvpn", "clash", "sing-box",
	"tailscale", "zerotier", "vmware", "virtualbox", "hyper-v", "vethernet",
	"tunnel", "loopback", "pseudo", "wan miniport", "bluetooth", "ndis",
	"filter", "qos", "bridge", "satellite", " Forti", "vpnkit", "wsl",
}

const (
	ifTypeEthernet = 6 // IF_TYPE_ETHERNET_CSMACD
	ifTypeWiFi     = 71
	ifOperStatusUp = 1

	gaaFlagIncludeGateways = 0x0200 // 让 FirstGatewayAddress 生效
)

// physicalInterfaces 枚举当前可用（up、有默认网关、非虚拟）的物理网卡，
// 按 IPv4 跃点升序（最前 = 当前上网主用网卡）。以太网/Wi-Fi 优先，
// 其它物理类型（蜂窝模组/USB 共享等）排在后面兜底。
func physicalInterfaces() []winIface {
	var size uint32
	_ = windows.GetAdaptersAddresses(windows.AF_UNSPEC, gaaFlagIncludeGateways, 0, nil, &size)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, gaaFlagIncludeGateways, 0, aa, &size); err != nil {
		return nil
	}
	var prim, other []winIface
	for p := aa; p != nil; p = p.Next {
		if p.OperStatus != ifOperStatusUp || p.FirstGatewayAddress == nil {
			continue // 未启用 / 无默认网关（不能上网的网卡不可能是当前主用）
		}
		name := windows.UTF16PtrToString(p.FriendlyName)
		desc := windows.UTF16PtrToString(p.Description)
		lower := strings.ToLower(name + " " + desc)
		virtual := false
		for _, kw := range virtualIfKeywords {
			if strings.Contains(lower, kw) {
				virtual = true
				break
			}
		}
		if virtual {
			continue
		}
		guid := windows.BytePtrToString(p.AdapterName)
		if guid == "" {
			continue
		}
		ifa := winIface{guid: guid, name: name, metric: p.Ipv4Metric}
		if p.IfType == ifTypeEthernet || p.IfType == ifTypeWiFi {
			prim = append(prim, ifa)
		} else {
			other = append(other, ifa)
		}
	}
	sortByMetric := func(s []winIface) {
		for i := 1; i < len(s); i++ { // 插入排序（网卡数量很小）
			for j := i; j > 0 && s[j].metric < s[j-1].metric; j-- {
				s[j], s[j-1] = s[j-1], s[j]
			}
		}
	}
	sortByMetric(prim)
	sortByMetric(other)
	return append(prim, other...)
}

// fillDNS 读取该网卡当前的 DNS 配置（接管前的快照，退出时恢复用）。
func (ifa *winIface) fillDNS() {
	var out []string
	seen := map[string]bool{}
	readKey := func(rootPath string) {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, rootPath+`\`+ifa.guid, registry.QUERY_VALUE)
		if err != nil {
			return
		}
		defer sk.Close()
		if v, _, err := sk.GetStringValue("NameServer"); err == nil {
			for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
				if validDNSIP(s) && !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
		if v, _, err := sk.GetStringValue("DhcpNameServer"); err == nil {
			for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
				if validDNSIP(s) && !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
	}
	readKey(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`)
	readKey(`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`)
	ifa.servers = out
	// NameServer 为空（纯 DHCP）时恢复用 dhcp；否则按静态列表还原
	ifa.dhcpDNS = len(out) == 0 || !registryHasStaticDNS(ifa.guid)
}

// registryHasStaticDNS 该网卡是否配置了静态 DNS（NameServer 非空）。
func registryHasStaticDNS(guid string) bool {
	for _, rootPath := range []string{
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`,
	} {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, rootPath+`\`+guid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := sk.GetStringValue("NameServer")
		sk.Close()
		if err == nil && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// activeInterfaceGUID 默认路由出口网卡的接口 GUID（注册表 Interfaces 下的键名，带花括号）。
// 链路：GetBestInterfaceEx(223.5.5.5) → ifIndex → ConvertInterfaceIndexToLuid
// → ConvertInterfaceLuidToGuid。全部走 iphlpapi，无需 cgo。
// 注意：VPN 虚拟网卡接管全局流量时本函数返回的是虚拟网卡，故只作兜底；
// 首选 physicalInterfaces 的物理网卡结果。
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
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
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

// dnsAllInterfaces 回退：合并全部网卡的 DNS（无法识别物理网卡时的旧行为）。
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
