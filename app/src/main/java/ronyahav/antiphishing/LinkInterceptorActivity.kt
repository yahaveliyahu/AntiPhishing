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
            if (url != null) forwardToBrowser(url, prefs)
            finish()
            return
        }

        // System is ON: Show debug toast and the dialog
        Toast.makeText(this, "AntiPhishing intercepted: $url", Toast.LENGTH_LONG).show()

        setContent {
            AntiPhishingTheme {
                AlertDialog(
                    onDismissRequest = {
                        forwardToBrowser(url, prefs)
                        finish()
                    },
                    title = { Text("AntiPhishing Alert") },
                    text = { Text("Do you want to scan this link before opening?\n\n$url") },
                    confirmButton = {
                        TextButton(onClick = {
                            Toast.makeText(this@LinkInterceptorActivity, "Simulating Scan...", Toast.LENGTH_SHORT).show()
                            forwardToBrowser(url, prefs)
                            finish()
                        }) {
                            Text("Scan Link")
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = {
                            forwardToBrowser(url, prefs)
                            finish()
                        }) {
                            Text("Open directly")
                        }
                    }
                )
            }
        }
    }

    private fun forwardToBrowser(url: String, prefs: android.content.SharedPreferences) {
        val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url))

        // Fetch saved target browser, default to Chrome
        var targetPackage = prefs.getString("target_browser", "com.android.chrome") ?: "com.android.chrome"

        // Verify if the target browser is still installed
        val isInstalled = try {
            packageManager.getPackageInfo(targetPackage, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }

        // If target is uninstalled, fallback silently to Chrome
        if (!isInstalled) {
            targetPackage = "com.android.chrome"
        }

        browserIntent.setPackage(targetPackage)
        browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        try {
            startActivity(browserIntent)
        } catch (e: Exception) {
            // Absolute fallback: strip the package and let the system try
            browserIntent.setPackage(null)
            startActivity(browserIntent)
        }
    }
}