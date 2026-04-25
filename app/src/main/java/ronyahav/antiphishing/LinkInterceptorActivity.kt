package ronyahav.antiphishing

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import ronyahav.antiphishing.core.ui.AntiPhishingTheme

class LinkInterceptorActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val url = intent.dataString

        val prefs = getSharedPreferences("AntiPhishingPrefs", Context.MODE_PRIVATE)
        val isActive = prefs.getBoolean("is_active", false)

        if (!isActive || url == null) {
            Log.d("AntiPhishing", "System OFF. Bypassing link: $url")
            Toast.makeText(this, "AntiPhishing OFF -> Forwarding", Toast.LENGTH_SHORT).show()
            if (url != null) forwardToBrowser(url)
            finish()
            return
        }

        // System is ON: Show debug toast and the dialog
        Toast.makeText(this, "AntiPhishing intercepted: $url", Toast.LENGTH_LONG).show()

        setContent {
            AntiPhishingTheme {
                AlertDialog(
                    onDismissRequest = {
                        forwardToBrowser(url)
                        finish()
                    },
                    title = { Text("AntiPhishing Alert") },
                    text = { Text("Do you want to scan this link before opening?\n\n$url") },
                    confirmButton = {
                        TextButton(onClick = {
                            Toast.makeText(this@LinkInterceptorActivity, "Simulating Scan...", Toast.LENGTH_SHORT).show()
                            forwardToBrowser(url)
                            finish()
                        }) {
                            Text("Scan Link")
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = {
                            forwardToBrowser(url)
                            finish()
                        }) {
                            Text("Open directly")
                        }
                    }
                )
            }
        }
    }

    private fun forwardToBrowser(url: String) {
        // Create an intent to view the URL
        val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url))

        // Find all apps that can handle this intent
        val resolveInfos = packageManager.queryIntentActivities(browserIntent, PackageManager.MATCH_DEFAULT_ONLY)

        // Find the first one that is NOT our app to avoid an infinite loop
        for (info in resolveInfos) {
            if (info.activityInfo.packageName != packageName) {
                browserIntent.setPackage(info.activityInfo.packageName)
                break
            }
        }

        browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            startActivity(browserIntent)
        } catch (e: Exception) {
            Toast.makeText(this, "Could not find an external browser", Toast.LENGTH_SHORT).show()
        }
    }
}