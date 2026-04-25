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
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.lifecycleScope
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import ronyahav.antiphishing.core.database.LinkDao
import ronyahav.antiphishing.core.database.ScannedLink
import ronyahav.antiphishing.core.ui.AntiPhishingTheme
import javax.inject.Inject

@AndroidEntryPoint
class LinkInterceptorActivity : ComponentActivity() {

    @Inject
    lateinit var linkDao: LinkDao

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val url = intent.dataString
        val prefs = getSharedPreferences("AntiPhishingPrefs", Context.MODE_PRIVATE)
        val isActive = prefs.getBoolean("is_active", false)

        if (!isActive || url == null) {
            if (url != null) forwardToBrowser(url, prefs)
            finish()
            return
        }

        setContent {
            AntiPhishingTheme {
                AlertDialog(
                    onDismissRequest = {
                        // If dialog is dismissed without selection, treat as safe/bypassed
                        processAndForward(url, isSuspicious = false, prefs = prefs)
                    },
                    title = { Text(stringResource(id = R.string.alert_title)) },
                    text = { Text(stringResource(id = R.string.alert_text) + "\n\n$url") },
                    confirmButton = {
                        val scanMsg = stringResource(id = R.string.simulating_scan)
                        TextButton(onClick = {
                            // User clicked "Scan Link" (Marked as Red/Suspicious for ML training)
                            Toast.makeText(this@LinkInterceptorActivity, scanMsg, Toast.LENGTH_SHORT).show()
                            processAndForward(url, isSuspicious = true, prefs = prefs)
                        }) {
                            Text(stringResource(id = R.string.scan_button))
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = {
                            // User clicked "Open directly" (Marked as Green/Safe, enters 5-link FIFO)
                            processAndForward(url, isSuspicious = false, prefs = prefs)
                        }) {
                            Text(stringResource(id = R.string.open_directly))
                        }
                    }
                )
            }
        }
    }

    // Handles the database insertion and navigates away immediately
    private fun processAndForward(url: String, isSuspicious: Boolean, prefs: android.content.SharedPreferences) {
        lifecycleScope.launch {
            // Generate a dummy risk score depending on user choice (Red vs Green)
            val dummyScore = if (isSuspicious) (70..100).random() else (0..30).random()

            val linkEntry = ScannedLink(
                url = url,
                isSuspicious = isSuspicious,
                riskScore = dummyScore,
                threatType = if (isSuspicious) "User Flagged / Scan Needed" else null
            )

            // Save to DB. Safe links are trimmed to 5, Suspicious links are kept forever.
            linkDao.insertAndTrim(linkEntry)

            // Forward to target browser and close interceptor
            forwardToBrowser(url, prefs)
            finish()
        }
    }

    private fun forwardToBrowser(url: String, prefs: android.content.SharedPreferences) {
        val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        var targetPackage = prefs.getString("target_browser", "com.android.chrome") ?: "com.android.chrome"

        val isInstalled = try {
            packageManager.getPackageInfo(targetPackage, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }

        if (!isInstalled) targetPackage = "com.android.chrome"
        browserIntent.setPackage(targetPackage)
        browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        try {
            startActivity(browserIntent)
        } catch (e: Exception) {
            // Fallback if no specific browser handles it
            browserIntent.setPackage(null)
            startActivity(browserIntent)
        }
    }
}