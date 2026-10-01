package com.fastime.app

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File

class MainActivity : Activity() {

    private lateinit var statusView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Android 13+ 需运行时申请通知权限，否则前台通知不显示（服务仍会运行）
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 1)
        }
        startForegroundService(Intent(this, CoreService::class.java))

        val dp = resources.displayMetrics.density
        statusView = TextView(this).apply {
            textSize = 14f
            setTextColor(Color.parseColor("#222222"))
            setPadding((20 * dp).toInt(), (16 * dp).toInt(), (20 * dp).toInt(), (16 * dp).toInt())
        }
        val title = TextView(this).apply {
            text = "Fastime"
            textSize = 22f
            setTextColor(Color.BLACK)
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(0, (32 * dp).toInt(), 0, (8 * dp).toInt())
        }
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(title)
            addView(statusView)
        }
        setContentView(ScrollView(this).apply { addView(col) })

        refreshStatus()
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    private fun refreshStatus() {
        val logFile = File(filesDir, "fastime.log")
        val tail = if (logFile.exists()) {
            logFile.readLines().takeLast(30).joinToString("\n")
        } else {
            "(暂无日志)"
        }
        statusView.text = buildString {
            append("核心服务已启动，正在后台常驻。\n")
            append("划掉或退出本界面不影响服务运行。\n\n")
            append("—— 最近日志 (${logFile.absolutePath}) ——\n")
            append(tail)
        }
    }
}
