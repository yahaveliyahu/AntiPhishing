package ronyahav.antiphishing

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
import androidx.lifecycle.lifecycleScope
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ronyahav.antiphishing.core.database.LinkDao
import ronyahav.antiphishing.core.database.ScannedLink
import ronyahav.antiphishing.core.ui.AntiPhishingTheme
import javax.inject.Inject

import androidx.compose.material3.Text
import androidx.compose.material3.TextButton

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
            AntiPhishingTheme { CheckingScreen(url = url) }
        }

        lifecycleScope.launch {
            // Step 1: Check URL against MongoDB via Flask
            val serverResult = withContext(Dispatchers.IO) {
                ApiClient.checkUrl(url)
            }

            // Step 2: Lexical analysis for Unknown links
            val finalResult: ApiClient.CheckResult = if (serverResult is ApiClient.CheckResult.Unknown) {
                val lexical = withContext(Dispatchers.Default) {
                    LexicalAnalyzer.analyze(url)
                }

                if (lexical.isObviouslyMalicious) {
                    // Unambiguous signal (e.g. @ symbol, javascript: URI, data: URI).
                    // Block immediately — no ML server call needed.
                    ApiClient.CheckResult.Malicious(
                        explanation = buildExplanation(lexical),
                        source = "Lexical Analysis",
                        confidence = 95,
                        matchType = "lexical"
                    )
                } else {
                    // The link is not in our database and shows no obvious malicious
                    // patterns. Surface it as "unknown" and let the user decide.
                    ApiClient.CheckResult.Unknown(
                        "This link is not in our database. We did not find obvious " +
                                "signs of phishing, but we could not fully verify it."
                    )
                }


                    // -------------------------------------------------------------------------------------

                    // Forward feature vector to Flask ML server (Step 3).
                    // The ML model makes the actual classification decision.
//                    withContext(Dispatchers.IO) {
//                        ApiClient.scoreLexical(url, lexical.features)
//                    }
//                }
            } else {
                serverResult
            }

            // Save result to local Room DB
            saveToLocalDb(url, finalResult)

            // Show toast when link is confirmed safe (whitelisted)
            if (finalResult is ApiClient.CheckResult.Whitelisted) {
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
                        result = finalResult,
                        onProceed = { forwardToBrowser(url, prefs); finish() },
                        onGoBack = { finish() }
                    )
                }
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Builds the user-facing explanation string from lexical flags. */
    private fun buildExplanation(lexical: LexicalAnalyzer.LexicalResult): String {
        return lexical.flags.take(3).joinToString("\n")
    }

    // ── Save to local Room DB ─────────────────────────────────────────────────
    private suspend fun saveToLocalDb(url: String, result: ApiClient.CheckResult) {
        val linkEntry = ScannedLink(
            url = url,
            isSuspicious = result is ApiClient.CheckResult.Malicious,
            riskScore = when (result) {
                is ApiClient.CheckResult.Whitelisted -> 0
                is ApiClient.CheckResult.Malicious -> result.confidence
                is ApiClient.CheckResult.Unknown -> 50
                is ApiClient.CheckResult.Error -> 50
                else -> 0
            },
            threatType = when (result) {
                is ApiClient.CheckResult.Malicious -> result.source
                else -> null
            }
        )
        linkDao.insertAndTrim(linkEntry)
    }

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
            modifier = Modifier.fillMaxSize().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            CircularProgressIndicator(modifier = Modifier.size(64.dp), strokeWidth = 4.dp)
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
 * ✅ Whitelisted → auto-proceeds, shows brief safe message
 * 🚨 Malicious → blocks, shows warning + explanation + source
 * 🔍 Unknown → shows "unknown" message, user can proceed
 * ⚠️ Error → shows error, user can proceed or go back
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
            modifier = Modifier.fillMaxSize().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            when (result) {
                // ── Malicious (DB blacklist OR lexical DANGEROUS) ──────────────
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

                // ── Unknown (should not reach here after Step 2, kept as safety net) ──
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

