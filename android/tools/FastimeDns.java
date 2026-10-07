// FastimeDns —— root/shell 模式下经 app_process 直接调用 Java 层系统服务，
// 输出「当前在用网络」的真实 DNS 服务器（每行一个 IP，去重）。
//
// 选取规则（与 fastime 需求一致）：
//  1. 只取正在使用的网络：Wi-Fi 在用就只要 Wi-Fi 的 DNS，蜂窝在用就只要蜂窝的，
//     绝不把没连上的网络 DNS 混进来。
//  2. 全隧道 VPN 接管时，「默认网络」是 VPN 虚拟网卡，其 DNS 是虚拟地址——
//     跳过 TRANSPORT_VPN，改挑物理网络（Wi-Fi > 蜂窝 > 有线）。
//  3. 双通道/双 Wi-Fi 加速（getMultipathPreference() != NONE，部分手机
//     Wi-Fi 与蜂窝同时承载流量）：两条网络的 DNS 都输出。
//
// 全程反射，不依赖任何私有 API 的编译时符号，javac + d8 即可构建。
//
// CI 构建（android/tools/build_dns_dex.sh）：
//   javac FastimeDns.java && d8 --min-api 21 → classes.dex → base64 → -ldflags -X 注入
//
// 运行（fastime 二进制内嵌 dex，root 时自动调用）：
//   app_process -Djava.class.path=/path/fastime-dns.dex /system/bin FastimeDns
public class FastimeDns {
    // NetworkCapabilities 传输类型常量（android.net.NetworkCapabilities）
    static final int TRANSPORT_CELLULAR = 0;
    static final int TRANSPORT_WIFI = 1;
    static final int TRANSPORT_ETHERNET = 3;
    static final int TRANSPORT_VPN = 4;

    // ConnectivityManager.MULTIPATH_PREFERENCE_NONE
    static final int MULTIPATH_NONE = 0;

    static final java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();

    public static void main(String[] args) {
        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Object binder = sm.getMethod("getService", String.class).invoke(null, "connectivity");
            if (binder == null) {
                return;
            }
            Class<?> stub = Class.forName("android.net.IConnectivityManager$Stub");
            Object cm = stub.getMethod("asInterface", Class.forName("android.os.IBinder"))
                    .invoke(null, binder);
            if (cm == null) {
                return;
            }
            Class<?> networkCls = Class.forName("android.net.Network");

            java.util.List<Object> all = allNetworks(cm);
            Object active = activeNetwork(cm);

            if (active != null) {
                Object caps = capsOf(cm, active, networkCls);
                if (caps != null && !hasTransport(caps, TRANSPORT_VPN)) {
                    // 正常情况：默认网络就是当前在用的物理网络
                    collectDns(cm, active, networkCls);
                } else {
                    // 全隧道 VPN：挑真实物理网络，Wi-Fi > 蜂窝 > 有线
                    collectPhysical(cm, all, networkCls);
                }
            } else {
                collectPhysical(cm, all, networkCls);
            }

            // 双通道：把「实际参与多路径传输」的其它网络也收进来
            for (Object n : all) {
                Object caps = capsOf(cm, n, networkCls);
                if (caps == null || hasTransport(caps, TRANSPORT_VPN)) {
                    continue;
                }
                if (multipathInUse(cm, n, networkCls)) {
                    collectDns(cm, n, networkCls);
                }
            }

            for (String ip : out) {
                System.out.println(ip);
            }
        } catch (Throwable ignore) {
            // 任何失败都静默退出，由 Go 侧回退到 dumpsys / getprop
        }
    }

    // 枚举全部网络
    static java.util.List<Object> allNetworks(Object cm) {
        java.util.List<Object> nets = new java.util.ArrayList<>();
        try {
            Object netsObj = cm.getClass().getMethod("getAllNetworks").invoke(cm);
            if (netsObj instanceof Object[]) {
                for (Object n : (Object[]) netsObj) {
                    if (n != null) {
                        nets.add(n);
                    }
                }
            }
        } catch (Throwable ignore) {
        }
        return nets;
    }

    // 当前默认网络：Android 12+ getActiveNetwork 可能带 callingPackage
    static Object activeNetwork(Object cm) {
        for (java.lang.reflect.Method m : cm.getClass().getMethods()) {
            if (!m.getName().equals("getActiveNetwork")) {
                continue;
            }
            try {
                Object n;
                if (m.getParameterTypes().length == 0) {
                    n = m.invoke(cm);
                } else {
                    n = m.invoke(cm, "com.android.shell");
                }
                if (n != null) {
                    return n;
                }
            } catch (Throwable ignore) {
            }
        }
        return null;
    }

    static Object capsOf(Object cm, Object network, Class<?> networkCls) {
        try {
            return cm.getClass().getMethod("getNetworkCapabilities", networkCls).invoke(cm, network);
        } catch (Throwable t) {
            return null;
        }
    }

    static boolean hasTransport(Object caps, int transport) {
        try {
            return (Boolean) caps.getClass().getMethod("hasTransport", int.class)
                    .invoke(caps, transport);
        } catch (Throwable t) {
            return false;
        }
    }

    // getMultipathPreference(network) != NONE 说明该网络正参与多路径传输
    //（OPPO/小米等的双通道加速），API 26+；低版本反射失败即视为无双通道。
    static boolean multipathInUse(Object cm, Object network, Class<?> networkCls) {
        try {
            Object r = cm.getClass().getMethod("getMultipathPreference", networkCls)
                    .invoke(cm, network);
            return r instanceof Integer && (Integer) r != MULTIPATH_NONE;
        } catch (Throwable t) {
            return false;
        }
    }

    // 物理网络优先级挑选：Wi-Fi > 蜂窝 > 有线，取第一个有 DNS 的
    static void collectPhysical(Object cm, java.util.List<Object> all, Class<?> networkCls) {
        Object best = null;
        int bestScore = -1;
        for (Object n : all) {
            Object caps = capsOf(cm, n, networkCls);
            if (caps == null || hasTransport(caps, TRANSPORT_VPN)) {
                continue;
            }
            int score;
            if (hasTransport(caps, TRANSPORT_WIFI)) {
                score = 3;
            } else if (hasTransport(caps, TRANSPORT_CELLULAR)) {
                score = 2;
            } else if (hasTransport(caps, TRANSPORT_ETHERNET)) {
                score = 1;
            } else {
                continue;
            }
            if (score > bestScore && hasDns(cm, n, networkCls)) {
                best = n;
                bestScore = score;
            }
        }
        if (best != null) {
            collectDns(cm, best, networkCls);
        }
    }

    static boolean hasDns(Object cm, Object network, Class<?> networkCls) {
        Object lp = linkProps(cm, network, networkCls);
        return lp != null && hasDnsServers(lp);
    }

    static Object linkProps(Object cm, Object network, Class<?> networkCls) {
        try {
            return cm.getClass().getMethod("getLinkProperties", networkCls).invoke(cm, network);
        } catch (Throwable t) {
            return null;
        }
    }

    static boolean hasDnsServers(Object lp) {
        try {
            Object servers = lp.getClass().getMethod("getDnsServers").invoke(lp);
            return servers instanceof java.util.List && !((java.util.List<?>) servers).isEmpty();
        } catch (Throwable t) {
            return false;
        }
    }

    // LinkProperties.getDnsServers() → List<InetAddress>，收进 out（自动去重、保序）
    static void collectDns(Object cm, Object network, Class<?> networkCls) {
        Object lp = linkProps(cm, network, networkCls);
        if (lp == null) {
            return;
        }
        try {
            Object servers = lp.getClass().getMethod("getDnsServers").invoke(lp);
            if (!(servers instanceof java.util.List)) {
                return;
            }
            for (Object a : (java.util.List<?>) servers) {
                Object host = a.getClass().getMethod("getHostAddress").invoke(a);
                if (host != null) {
                    out.add(host.toString());
                }
            }
        } catch (Throwable ignore) {
        }
    }
}
