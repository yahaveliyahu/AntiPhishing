package ronyahav.antiphishing

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.lifecycle.lifecycleScope
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import ronyahav.antiphishing.core.database.LinkDao
import ronyahav.antiphishing.core.database.ScannedLink
import ronyahav.antiphishing.core.ui.AntiPhishingTheme
import javax.inject.Inject

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@AndroidEntryPoint
class LinkInterceptorActivity : ComponentActivity() {

    @Inject
    lateinit var linkDao: LinkDao

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val url = intent.dataString
        val prefs = getSharedPreferences("AntiPhishingPrefs", MODE_PRIVATE)
        val isActive = prefs.getBoolean("is_active", false)

        // If protection is off or no URL — forward directly
        if (!isActive || url == null) {
            if (url != null) forwardToBrowser(url, prefs)
            finish()
            return
        }

        // Show loading state while checking the URL
        setContent {
            AntiPhishingTheme {
                CheckingScreen(url = url)
            }
        }

        // Check URL against MongoDB via Flask
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                ApiClient.checkUrl(url)
            }

            // Save result to local Room DB
            saveToLocalDb(url, result)

            // Show toast when link is confirmed safe (whitelisted)
            if (result is ApiClient.CheckResult.Whitelisted) {
                Toast.makeText(
                    this@LinkInterceptorActivity,
                    "The link you entered is not malicious. You are safe 😊",
                    Toast.LENGTH_SHORT
                ).show()
            }

            // Update UI based on result
            setContent {
                AntiPhishingTheme {
                    ResultScreen(
                        url = url,
                        result = result,
                        onProceed = { forwardToBrowser(url, prefs); finish() },
                        onGoBack = { finish() }
                    )
                }
            }
        }
    }

    // ── Save to local Room DB ─────────────────────────────────────────────────

    private suspend fun saveToLocalDb(url: String, result: ApiClient.CheckResult) {
        val linkEntry = ScannedLink(
            url          = url,
            isSuspicious = result is ApiClient.CheckResult.Malicious,
            riskScore    = when (result) {
                is ApiClient.CheckResult.Whitelisted -> 0
                is ApiClient.CheckResult.Malicious   -> result.confidence
                is ApiClient.CheckResult.Unknown     -> 50
                is ApiClient.CheckResult.Error       -> 50
            },
            threatType   = when (result) {
                is ApiClient.CheckResult.Malicious -> result.source
                else -> null
            }
        )
        linkDao.insertAndTrim(linkEntry)
    }

//                AlertDialog(
//                    onDismissRequest = {
//                        // If dialog is dismissed without selection, treat as safe/bypassed
//                        processAndForward(url, isSuspicious = false, prefs = prefs)
//                    },
//                    title = { Text(stringResource(id = R.string.alert_title)) },
//                    text = { Text(stringResource(id = R.string.alert_text) + "\n\n$url") },
//                    confirmButton = {
//                        val scanMsg = stringResource(id = R.string.simulating_scan)
//                        TextButton(onClick = {
//                            // User clicked "Scan Link" (Marked as Red/Suspicious for ML training)
//                            Toast.makeText(this@LinkInterceptorActivity, scanMsg, Toast.LENGTH_SHORT).show()
//                            processAndForward(url, isSuspicious = true, prefs = prefs)
//                        }) {
//                            Text(stringResource(id = R.string.scan_button))
//                        }
//                    },
//                    dismissButton = {
//                        TextButton(onClick = {
//                            // User clicked "Open directly" (Marked as Green/Safe, enters 5-link FIFO)
//                            processAndForward(url, isSuspicious = false, prefs = prefs)
//                        }) {
//                            Text(stringResource(id = R.string.open_directly))
//                        }
//                    }
//                )
//            }
//        }
//    }

//    // Handles the database insertion and navigates away immediately
//    private fun processAndForward(url: String, isSuspicious: Boolean, prefs: android.content.SharedPreferences) {
//        lifecycleScope.launch {
//            // Generate a dummy risk score depending on user choice (Red vs Green)
//            val dummyScore = if (isSuspicious) (70..100).random() else (0..30).random()
//
//            val linkEntry = ScannedLink(
//                url = url,
//                isSuspicious = isSuspicious,
//                riskScore = dummyScore,
//                threatType = if (isSuspicious) "User Flagged / Scan Needed" else null
//            )
//
//            // Save to DB. Safe links are trimmed to 5, Suspicious links are kept forever.
//            linkDao.insertAndTrim(linkEntry)
//
//            // Forward to target browser and close interceptor
//            forwardToBrowser(url, prefs)
//            finish()
//        }
//    }

    // ── Forward to browser ────────────────────────────────────────────────────

    private fun forwardToBrowser(url: String, prefs: android.content.SharedPreferences) {
        val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        var targetPackage = prefs.getString("target_browser", "com.android.chrome") ?: "com.android.chrome"

        val isInstalled = try {
            packageManager.getPackageInfo(targetPackage, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }

        if (!isInstalled) targetPackage = "com.android.chrome"
        browserIntent.setPackage(targetPackage)
        browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        try {
            startActivity(browserIntent)
        } catch (_: Exception) {
            // Fallback if no specific browser handles it
            browserIntent.setPackage(null)
            startActivity(browserIntent)
        }
    }
}

// ── Composables ───────────────────────────────────────────────────────────────

/**
 * Shown while waiting for the Flask server response.
 */
@Composable
fun CheckingScreen(url: String) {
    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(64.dp),
                strokeWidth = 4.dp
            )
            Spacer(modifier = Modifier.height(24.dp))
            Text(
                text = "🔍 Checking link safety...",
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = url.take(60) + if (url.length > 60) "..." else "",
                fontSize = 12.sp,
                color = Color.Gray,
                textAlign = TextAlign.Center,
                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
            )
        }
    }
}

/**
 * Shows the check result with appropriate message and actions.
 *
 * ✅ Whitelisted  → auto-proceeds, shows brief safe message
 * 🚨 Malicious   → blocks, shows warning + explanation + source
 * 🔍 Unknown     → shows "unknown" message, user can proceed
 * ⚠️ Error       → shows error, user can proceed or go back
 */
@Composable
fun ResultScreen(
    url: String,
    result: ApiClient.CheckResult,
    onProceed: () -> Unit,
    onGoBack: () -> Unit
) {
    // Auto-proceed for whitelisted URLs
    if (result is ApiClient.CheckResult.Whitelisted) {
        LaunchedEffect(Unit) { onProceed() }
        CheckingScreen(url = url) // Show brief loading while auto-proceeding
        return
    }

    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            when (result) {

                // ── Malicious ─────────────────────────────────────────────
                is ApiClient.CheckResult.Malicious -> {
                    Text(text = "🚨", fontSize = 64.sp)
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Malicious Link Detected!",
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFC62828),
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.height(16.dp))

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = Color(0xFFFFEBEE)
                        )
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            // URL
                            Text(
                                text = url.take(70) + if (url.length > 70) "..." else "",
                                fontSize = 12.sp,
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                color = Color.Gray
                            )
                            Spacer(modifier = Modifier.height(12.dp))

                            // Explanation
                            Text(
                                text = result.explanation,
                                fontSize = 15.sp,
                                lineHeight = 22.sp
                            )
                            Spacer(modifier = Modifier.height(8.dp))

                            // Source
                            if (result.source != null) {
                                Text(
                                    text = "Source: ${result.source}",
                                    fontSize = 13.sp,
                                    color = Color.Gray
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    // Primary action — go back
                    Button(
                        onClick = onGoBack,
                        modifier = Modifier.fillMaxWidth().height(52.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF1976D2)
                        )
                    ) {
                        Text("← Go Back (Recommended)", fontSize = 16.sp)
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Secondary action — open anyway at own risk
                    TextButton(
                        onClick = onProceed,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = "Open Anyway (At Your Own Risk)",
                            color = Color(0xFFC62828),
                            fontSize = 14.sp
                        )
                    }
                }

                // ── Unknown ───────────────────────────────────────────────
                is ApiClient.CheckResult.Unknown -> {
                    Text(text = "🔍", fontSize = 64.sp)
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Unknown Link",
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFE65100),
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.height(16.dp))

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = Color(0xFFFFF3E0)
                        )
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                text = url.take(70) + if (url.length > 70) "..." else "",
                                fontSize = 12.sp,
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                color = Color.Gray
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Text(
                                text = "This link is unknown — we could not determine whether it is malicious or safe. Proceed with caution.",
                                fontSize = 15.sp,
                                lineHeight = 22.sp
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    Button(
                        onClick = onProceed,
                        modifier = Modifier.fillMaxWidth().height(52.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFFE65100)
                        )
                    ) {
                        Text("Open Link", fontSize = 16.sp)
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    TextButton(
                        onClick = onGoBack,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Go Back", color = Color.Gray, fontSize = 14.sp)
                    }
                }

                // ── Error ─────────────────────────────────────────────────
                is ApiClient.CheckResult.Error -> {
                    Text(text = "⚠️", fontSize = 64.sp)
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Could Not Check Link",
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFE65100),
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.height(16.dp))

                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                text = "Server unreachable. The link could not be verified.",
                                fontSize = 15.sp,
                                lineHeight = 22.sp
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = result.message,
                                fontSize = 12.sp,
                                color = Color.Gray
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    Button(
                        onClick = onProceed,
                        modifier = Modifier.fillMaxWidth().height(52.dp)
                    ) {
                        Text("Open Anyway", fontSize = 16.sp)
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    TextButton(
                        onClick = onGoBack,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Go Back", color = Color.Gray, fontSize = 14.sp)
                    }
                }

                else -> {} // Whitelisted handled above
            }
        }
    }
}

