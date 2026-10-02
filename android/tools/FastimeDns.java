// FastimeDns —— root/shell 模式下经 app_process 直接调用 Java 层系统服务，
// 输出当前默认网络的 LinkProperties.getDnsServers()（与 APK Java 推送同源同精度）。
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
            // getActiveLinkProperties()：Android ≤11 无参，Android 12+ 带 callingPackage
            Object lp = null;
            for (java.lang.reflect.Method m : cm.getClass().getMethods()) {
                if (!m.getName().equals("getActiveLinkProperties")) {
                    continue;
                }
                try {
                    if (m.getParameterTypes().length == 0) {
                        lp = m.invoke(cm);
                    } else {
                        lp = m.invoke(cm, "com.android.shell");
                    }
                } catch (Throwable ignore) {
                }
                if (lp != null) {
                    break;
                }
            }
            if (lp == null) {
                return;
            }
            // LinkProperties.getDnsServers() → List<InetAddress>，逐行输出
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
            // 任何失败都静默退出，由 Go 侧回退到 dumpsys / getprop
        }
    }
}
