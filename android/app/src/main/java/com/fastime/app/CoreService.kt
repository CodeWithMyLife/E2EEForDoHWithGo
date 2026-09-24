package com.fastime.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
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

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundWithNotification()
        acquireWakeLock()
        if (!running) {
            running = true
            Thread { runRelayWithWatchdog() }.start()
        }
        return START_STICKY
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
        super.onDestroy()
    }
}
