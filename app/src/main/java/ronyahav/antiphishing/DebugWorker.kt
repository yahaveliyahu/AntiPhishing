package ronyahav.antiphishing

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.work.Worker
import androidx.work.WorkerParameters

class DebugWorker(
    private val context: Context,
    workerParams: WorkerParameters
) : Worker(context, workerParams) {

    override fun doWork(): Result {
        // Double check if protection is active before doing anything
        val prefs = context.getSharedPreferences("AntiPhishingPrefs", Context.MODE_PRIVATE)
        val isActive = prefs.getBoolean("is_active", false)

        if (!isActive) {
            Log.d("AntiPhishing", "Worker cancelled - Protection is OFF")
            return Result.success()
        }

        Log.d("AntiPhishing", "ALIVE: Background worker is running!")
        showDebugNotification()

        return Result.success()
    }

    private fun showDebugNotification() {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channelId = "debug_channel"

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "Debug Notifications",
                NotificationManager.IMPORTANCE_LOW // Low importance so it doesn't ring/vibrate
            )
            manager.createNotificationChannel(channel)
        }

        val notification = NotificationCompat.Builder(context, channelId)
            .setContentTitle("AntiPhishing Debug")
            .setContentText("System is ALIVE and monitoring links.")
            .setSmallIcon(android.R.drawable.ic_secure)
            .build()

        manager.notify(101, notification)
    }
}