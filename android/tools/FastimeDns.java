// FastimeDns —— root/shell 模式下经 app_process 直接调用 Java 层系统服务，
// 输出当前真实物理网络的 DNS 服务器（与 APK Java 推送同源同精度）。
//
// VPN/代理类程序会创建虚拟网络强制接管全局流量，此时"当前默认网络"可能
// 变成 VPN 网络，其 DNS 是虚拟/代理地址——所以本工具枚举全部网络，
// 跳过 TRANSPORT_VPN，优先取 Wi-Fi > 蜂窝 > 有线的 LinkProperties DNS。
// 枚举失败时回退旧的 getActiveLinkProperties 途径。
//
// 全程反射，不依赖任何私有 API 的编译时符号（android.jar 里没有
// IConnectivityManager / ServiceManager），因此用普通 javac + d8 即可构建。
//
// CI 构建（android/tools/build_dns_dex.sh）：
//   javac FastimeDns.java && d8 --min-api 21 → classes.dex → base64 → -ldflags -X 注入
//
// 运行（fastime 二进制内嵌 dex，root 时自动调用）：
//   app_process -Djava.class.path=/path/fastime_dns.dex /system/bin FastimeDns
public class FastimeDns {
    // NetworkCapabilities 传输类型常量（android.net.NetworkCapabilities）
    static final int TRANSPORT_CELLULAR = 0;
    static final int TRANSPORT_WIFI = 1;
    static final int TRANSPORT_ETHERNET = 3;
    static final int TRANSPORT_VPN = 4;

    public static void main(String[] args) {
        try {
            // android.os.ServiceManager.getService("connectivity") → binder 句柄
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Object binder = sm.getMethod("getService", String.class).invoke(null, "connectivity");
            if (binder == null) {
                return;
            }
            // IConnectivityManager.Stub.asInterface(binder)
            Class<?> stub = Class.forName("android.net.IConnectivityManager$Stub");
            Object cm = stub.getMethod("asInterface", Class.forName("android.os.IBinder"))
                    .invoke(null, binder);
            if (cm == null) {
                return;
            }
            // 首选：枚举全部网络，跳过 VPN，挑真实物理网络的 DNS
            if (printPhysicalNetworkDns(cm)) {
                return;
            }
            // 兜底：当前默认网络的 LinkProperties（旧行为）
            Object lp = activeLinkProperties(cm);
            printDnsServers(lp);
        } catch (Throwable ignore) {
            // 任何失败都静默退出，由 Go 侧回退到 dumpsys / getprop
        }
    }

    // 枚举 getAllNetworks()，跳过 TRANSPORT_VPN，按 Wi-Fi > 蜂窝 > 有线 优先级
    // 挑第一个有 DNS 服务器的网络，输出其 LinkProperties.getDnsServers()。
    static boolean printPhysicalNetworkDns(Object cm) {
        try {
            Object netsObj = cm.getClass().getMethod("getAllNetworks").invoke(cm);
            if (!(netsObj instanceof Object[])) {
                return false;
            }
            Object best = null; // LinkProperties
            int bestScore = -1;
            for (Object n : (Object[]) netsObj) {
                if (n == null) {
                    continue;
                }
                Object caps;
                try {
                    caps = cm.getClass().getMethod("getNetworkCapabilities",
                            Class.forName("android.net.Network")).invoke(cm, n);
                } catch (Throwable t) {
                    continue;
                }
                if (caps == null) {
                    continue;
                }
                java.lang.reflect.Method hasTransport = caps.getClass().getMethod("hasTransport", int.class);
                if ((Boolean) hasTransport.invoke(caps, TRANSPORT_VPN)) {
                    continue; // VPN 虚拟网络：跳过
                }
                int score;
                if ((Boolean) hasTransport.invoke(caps, TRANSPORT_WIFI)) {
                    score = 3;
                } else if ((Boolean) hasTransport.invoke(caps, TRANSPORT_CELLULAR)) {
                    score = 2;
                } else if ((Boolean) hasTransport.invoke(caps, TRANSPORT_ETHERNET)) {
                    score = 2;
                } else {
                    score = 1;
                }
                if (score <= bestScore) {
                    continue;
                }
                Object lp;
                try {
                    lp = cm.getClass().getMethod("getLinkProperties",
                            Class.forName("android.net.Network")).invoke(cm, n);
                } catch (Throwable t) {
                    continue;
                }
                if (lp != null && hasDns(lp)) {
                    best = lp;
                    bestScore = score;
                }
            }
            if (best != null) {
                printDnsServers(best);
                return true;
            }
        } catch (Throwable ignore) {
        }
        return false;
    }

    // getActiveLinkProperties()：Android ≤11 无参，Android 12+ 带 callingPackage
    static Object activeLinkProperties(Object cm) {
        for (java.lang.reflect.Method m : cm.getClass().getMethods()) {
            if (!m.getName().equals("getActiveLinkProperties")) {
                continue;
            }
            Object lp = null;
            try {
                if (m.getParameterTypes().length == 0) {
                    lp = m.invoke(cm);
                } else {
                    lp = m.invoke(cm, "com.android.shell");
                }
            } catch (Throwable ignore) {
            }
            if (lp != null) {
                return lp;
            }
        }
        return null;
    }

    static boolean hasDns(Object lp) {
        try {
            Object servers = lp.getClass().getMethod("getDnsServers").invoke(lp);
            return servers instanceof java.util.List && !((java.util.List<?>) servers).isEmpty();
        } catch (Throwable t) {
            return false;
        }
    }

    // LinkProperties.getDnsServers() → List<InetAddress>，逐行输出
    static void printDnsServers(Object lp) {
        try {
            if (lp == null) {
                return;
            }
            Object servers = lp.getClass().getMethod("getDnsServers").invoke(lp);
            if (!(servers instanceof java.util.List)) {
                return;
            }
            for (Object a : (java.util.List<?>) servers) {
                Object host = a.getClass().getMethod("getHostAddress").invoke(a);
                if (host != null) {
                    System.out.println(host);
                }
            }
        } catch (Throwable ignore) {
        }
    }
}
