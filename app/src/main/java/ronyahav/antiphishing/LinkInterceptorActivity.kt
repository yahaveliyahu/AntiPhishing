package ronyahav.antiphishing

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
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

        // Check if the system is turned ON or OFF
        val prefs = getSharedPreferences("AntiPhishingPrefs", Context.MODE_PRIVATE)
        val isActive = prefs.getBoolean("is_active", false)

        if (!isActive || url == null) {
            // System is OFF: Let the user pass to the browser silently
            if (url != null) forwardToBrowser(url)
            finish()
            return
        }

        // System is ON: Show the standard system dialog
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
                            // Temporarily forwarding to browser after "scan" for PoC
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
        val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url))

        // Find the default browser to avoid opening ourselves in a loop
        val resolveInfo = packageManager.resolveActivity(browserIntent, PackageManager.MATCH_DEFAULT_ONLY)
        if (resolveInfo != null && resolveInfo.activityInfo.packageName != packageName) {
            browserIntent.setPackage(resolveInfo.activityInfo.packageName)
        }

        browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            startActivity(browserIntent)
        } catch (e: Exception) {
            Toast.makeText(this, "Could not find a browser", Toast.LENGTH_SHORT).show()
        }
    }
}