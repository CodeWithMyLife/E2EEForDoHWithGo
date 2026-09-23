package com.fastime.app

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Android 13+ 需运行时申请通知权限，否则前台通知不显示（服务仍会运行）
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 1)
        }
        startForegroundService(Intent(this, CoreService::class.java))
        finish() // 启动服务后即退出界面，服务在后台常驻
    }
}
