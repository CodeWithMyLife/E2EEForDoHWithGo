package fastime

import (
	"reflect"
	"testing"
)

func TestValidDNSIP(t *testing.T) {
	good := []string{"223.5.5.5", "240e:f:a::8", "192.168.1.1", " 10.0.0.1 "}
	bad := []string{"0.0.0.0", "::", "", "abc", "999.1.1.1", "0.0.0.0,"}
	for _, s := range good {
		if !validDNSIP(s) {
			t.Errorf("validDNSIP(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validDNSIP(s) {
			t.Errorf("validDNSIP(%q) = true, want false", s)
		}
	}
}

// Android 10+ 单行格式：NetworkAgentInfo{ ... network{id} ... DnsAddresses: [...] }
const dumpSingleLine = `ConnectivityService:
Active default network: 5301
...
NetworkAgentInfo{ ni{[type: WIFI[], state: CONNECTED/CONNECTED]} network{5302} nethandle{123456} lp{{InterfaceName: wlan0 LinkAddresses: [ fe80::1/64,192.168.5.116/24 ] DnsAddresses: [ /192.168.5.1,/240e:f:a::8 ] Routes: [...]}} Score{50}}
NetworkAgentInfo{ ni{[type: MOBILE[LTE], state: CONNECTED/CONNECTED]} network{5301} nethandle{789012} lp{{InterfaceName: rmnet_data1 LinkAddresses: [ 10.165.42.71/30 ] DnsAddresses: [ /211.137.130.2,/211.137.130.18,/0.0.0.0,/:: ] ...}} Score{70}}
`

func TestDnsFromConnectivityDump_SingleLine(t *testing.T) {
	got := dnsFromConnectivityDump(dumpSingleLine)
	// 活跃网络是 5301（移动数据）：只取它的 DNS，且过滤 0.0.0.0/::
	want := []string{"211.137.130.2", "211.137.130.18"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Android 8/9 多行格式：块头含 "- id)"，DnsAddresses 在后续缩进行
const dumpMultiLine = `Active default network: 100

NetworkAgentInfo [WIFI () - 101]:
  Network: 101
  LinkProperties: { InterfaceName: wlan0
    LinkAddresses: [ 192.168.1.116/24 ]
    DnsAddresses: [ /192.168.1.1 ]
  }
NetworkAgentInfo [MOBILE (LTE) - 100]:
  Network: 100
  LinkProperties: { InterfaceName: rmnet0
    DnsAddresses: [ /211.136.112.50,/211.136.150.66 ]
  }
`

func TestDnsFromConnectivityDump_MultiLine(t *testing.T) {
	got := dnsFromConnectivityDump(dumpMultiLine)
	want := []string{"211.136.112.50", "211.136.150.66"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestDnsFromConnectivityDump_NoActive(t *testing.T) {
	if got := dnsFromConnectivityDump("no active line here\nDnsAddresses: [ /1.1.1.1 ]"); got != nil {
		t.Errorf("got %v, want nil（无活跃网络信息时不该乱猜）", got)
	}
}

// VPN 接管全局流量：活跃网络是 VPN（虚拟 DNS），应跳过它取底层 Wi-Fi 的真实 DNS
const dumpVPNActive = `ConnectivityService:
Active default network: 5303
...
NetworkAgentInfo{ ni{[type: WIFI[], state: CONNECTED/CONNECTED]} network{5302} lp{{InterfaceName: wlan0 LinkAddresses: [ 192.168.5.116/24 ] DnsAddresses: [ /192.168.5.1,/240e:f:a::8 ] ...}} Score{50}}
NetworkAgentInfo{ ni{[type: VPN[], state: CONNECTED/CONNECTED]} network{5303} lp{{InterfaceName: tun0 LinkAddresses: [ 198.18.0.2/32 ] DnsAddresses: [ /198.18.0.2 ] ...}} Score{70}}
`

func TestDnsFromConnectivityDump_VPNActive(t *testing.T) {
	got := dnsFromConnectivityDump(dumpVPNActive)
	// 活跃网络 5303 是 VPN：跳过，取底层 Wi-Fi 的真实 DNS，不要 198.18.0.2
	want := []string{"192.168.5.1", "240e:f:a::8"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// VPN 接管且只有蜂窝底层网络：取蜂窝 DNS
func TestDnsFromConnectivityDump_VPNActiveCellular(t *testing.T) {
	dump := `Active default network: 200
NetworkAgentInfo{ ni{[type: MOBILE[LTE], state: CONNECTED/CONNECTED]} network{201} lp{{DnsAddresses: [ /211.137.130.2,/211.137.130.18,/0.0.0.0 ] ...}} Score{70}}
NetworkAgentInfo{ ni{[type: VPN[], state: CONNECTED/CONNECTED]} network{200} lp{{DnsAddresses: [ /28.0.0.2 ] ...}} Score{50}}
`
	got := dnsFromConnectivityDump(dump)
	want := []string{"211.137.130.2", "211.137.130.18"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// 活跃网络本身就是 Wi-Fi（无 VPN）：行为不变
func TestDnsFromConnectivityDump_NoVPN(t *testing.T) {
	got := dnsFromConnectivityDump(dumpSingleLine)
	want := []string{"211.137.130.2", "211.137.130.18"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestDnsFromDumpAny_FiltersJunk(t *testing.T) {
	dump := "DNS servers: [ /192.168.1.1,/0.0.0.0,/::,/2409:8070:2000:f110::1 ]\nother line"
	got := dnsFromDumpAny(dump, "DNS")
	want := []string{"192.168.1.1", "2409:8070:2000:f110::1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
