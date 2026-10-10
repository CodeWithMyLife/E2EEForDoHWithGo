package com.fastime.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import java.io.File

/**
 * 常驻前台服务：
 * 1. 前台通知 + START_STICKY，系统杀死后自动拉起
 * 2. PARTIAL_WAKE_LOCK，息屏不休眠
 * 3. 执行内嵌的 Go 核心二进制（jniLibs 里的 libfastime.so），
 *    进程意外退出时由看门狗线程 3 秒后重启
 * 4. 网络切换由 Go 进程内置 watcher 感知（2s 轮询接口指纹），无需 Java 侧回调
 */
class CoreService : Service() {

    @Volatile private var running = false
    private var process: Process? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var dnsCallback: ConnectivityManager.NetworkCallback? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundWithNotification()
        acquireWakeLock()
        syncSystemDns()
        if (!running) {
            running = true
            Thread { runRelayWithWatchdog() }.start()
        }
        return START_STICKY
    }

    /**
     * 把当前在用网络的真实 DNS（DHCP/运营商下发）写入 filesDir/sysdns.txt，
     * 供 Go 核心应答 system-dns.com。跳过 VPN 虚拟网络；双通道
     * （Wi-Fi+蜂窝同时承载）时两路 DNS 都写入。切网/DNS 变化即时更新。
     */
    private fun syncSystemDns() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        fun writeCur() {
            val out = linkedSetOf<String>()
            val active = cm.activeNetwork
            val nets = cm.allNetworks.filter { n ->
                val caps = cm.getNetworkCapabilities(n) ?: return@filter false
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
            // 当前默认网络优先；多路径参与的网络一并收进来
            val chosen = nets.filter { it == active } +
                nets.filter { it != active && cm.getMultipathPreference(it) != 0 }
            for (n in chosen) {
                cm.getLinkProperties(n)?.dnsServers?.forEach {
                    it.hostAddress?.let(out::add)
                }
            }
            if (out.isNotEmpty()) {
                runCatching { File(filesDir, "sysdns.txt").writeText(out.joinToString("\n")) }
            }
        }
        writeCur()
        if (dnsCallback == null) {
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = writeCur()
                override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = writeCur()
            }
            runCatching { cm.registerDefaultNetworkCallback(cb) }
            dnsCallback = cb
        }
    }

    private fun startForegroundWithNotification() {
        val channelId = "fastime"
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(channelId, "Fastime", NotificationManager.IMPORTANCE_MIN)
        )
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val n: Notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("Fastime 运行中")
            .setContentText("本地加速服务")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, n)
        }
    }

    private fun acquireWakeLock() {
        val pm = getSystemService(PowerManager::class.java)
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "fastime:core").apply {
            acquire()
        }
    }

    private fun runRelayWithWatchdog() {
        // nativeLibraryDir 下的 libfastime.so 即 Go 二进制（extractNativeLibs 已释放为文件）
        val bin = File(applicationInfo.nativeLibraryDir, "libfastime.so")
        while (running) {
            try {
                bin.setExecutable(true, true)
                val p = ProcessBuilder(bin.absolutePath)
                    .directory(filesDir) // 工作目录设为 filesDir，fastime.log 落在应用私有目录
                    .redirectErrorStream(true)
                    .start()
                process = p
                p.inputStream.bufferedReader().forEachLine { /* 日志可接 logcat */ }
                p.waitFor()
            } catch (_: Throwable) {
            }
            if (running) Thread.sleep(3000) // 看门狗：3 秒后拉起
        }
    }

    override fun onDestroy() {
        running = false
        process?.destroy()
        wakeLock?.release()
        dnsCallback?.let {
            runCatching {
                getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(it)
            }
        }
        dnsCallback = null
        super.onDestroy()
    }
}
