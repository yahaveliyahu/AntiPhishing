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
import dagger.hilt.android.EntryPointAccessors
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
                        forwardToBrowser(url, prefs)
                        finish()
                    },
                    title = { Text(stringResource(id = R.string.alert_title)) },
                    text = { Text(stringResource(id = R.string.alert_text) + "\n\n$url") },
                    confirmButton = {
                        val scanMsg = stringResource(id = R.string.simulating_scan)
                        TextButton(onClick = {
                            Toast.makeText(this@LinkInterceptorActivity, scanMsg, Toast.LENGTH_SHORT).show()

                            // Perform initial heuristic analysis and save to DB
                            analyzeAndSave(url)

                            forwardToBrowser(url, prefs)
                            finish()
                        }) {
                            Text(stringResource(id = R.string.scan_button))
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = {
                            forwardToBrowser(url, prefs)
                            finish()
                        }) {
                            Text(stringResource(id = R.string.open_directly))
                        }
                    }
                )
            }
        }
    }

    private fun analyzeAndSave(url: String) {
        lifecycleScope.launch {
            // Simple heuristic check for PoC: if URL contains sensitive keywords, mark as suspicious
            val suspiciousKeywords = listOf("login", "verify", "secure", "update", "bank", "free", "phish")
            val isSuspicious = suspiciousKeywords.any { url.lowercase().contains(it) }

            // Generate a dummy risk score
            val dummyScore = if (isSuspicious) (70..100).random() else (0..30).random()

            val linkEntry = ScannedLink(
                url = url,
                isSuspicious = isSuspicious,
                riskScore = dummyScore,
                threatType = if (isSuspicious) "Suspicious Keyword Detected" else null
            )

            // Uses our smart DAO logic: Keep Red links, FIFO (max 5) for Green links
            linkDao.insertAndTrim(linkEntry)
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
            browserIntent.setPackage(null)
            startActivity(browserIntent)
        }
    }
}