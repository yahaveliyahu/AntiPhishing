package ronyahav.antiphishing

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import ronyahav.local.LocalUrlLists
import ronyahav.local.LocalUrlResult
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

        val url = extractIncomingUrl(intent)
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
            val serverResult = if (IS_LOCAL) {
                checkLocalLists(url)
            } else {
                withContext(Dispatchers.IO) {
                    ApiClient.checkUrl(url)
                }
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
                    // Step 3 (ML model) not built yet.
                    // Show a Toast to confirm the lexical analyzer ran successfully,
                    // then allow the link through so testing is not blocked.
                    val riskScore = lexical.features["lexical_risk_score"] ?: 0
                    withContext(Dispatchers.Main) {
                        Toast.makeText(
                            this@LinkInterceptorActivity,
                            "Step 3 not built yet. Lexical analysis complete. Risk score: $riskScore",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                    // Return Unknown so the user sees the neutral screen and can choose to proceed
                    ApiClient.CheckResult.Unknown(
                        "Lexical analysis complete (score: $riskScore). " +
                                "Step 3 ML model not built yet — cannot make final decision."
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

            // Save result to local Room DB immediately — the link is what it is,
            // regardless of what the user decides to do next.
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

    /**
     * Extracts the URL from the incoming intent.
     * Handles direct link interception (ACTION_VIEW) as well as
     * text shared from other apps (ACTION_SEND, ACTION_PROCESS_TEXT).
     */
    private fun extractIncomingUrl(intent: Intent): String? {
        intent.dataString
            ?.takeIf { it.startsWith("http://") || it.startsWith("https://") }
            ?.let { return it }

        val sharedText = when (intent.action) {
            Intent.ACTION_SEND -> intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
            Intent.ACTION_PROCESS_TEXT -> intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
            else -> null
        }

        return sharedText?.let(::extractUrlFromText)
    }

    private fun extractUrlFromText(text: String): String? {
        val urlPattern = Regex("""https?://[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?""")
        val rawUrl = urlPattern.find(text)?.value
            ?.trimEnd('.', ',', ';', ')', ']', '}')
            ?: return null

        return if (rawUrl.startsWith("http://") || rawUrl.startsWith("https://")) {
            rawUrl
        } else {
            "https://$rawUrl"
        }
    }

    /** Used in dev/local mode instead of hitting the Flask server. */
    private fun checkLocalLists(url: String): ApiClient.CheckResult {
        return when (val result = LocalUrlLists.check(url)) {
            is LocalUrlResult.Whitelisted -> ApiClient.CheckResult.Whitelisted(
                description = result.description,
                category = "local_whitelist"
            )

            is LocalUrlResult.Blacklisted -> ApiClient.CheckResult.Malicious(
                explanation = result.explanation,
                source = "Local blacklist: ${result.domain}",
                confidence = 100,
                matchType = "local_domain"
            )

            LocalUrlResult.Unknown -> ApiClient.CheckResult.Unknown(
                "No match in local whitelist or blacklist."
            )
        }
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
                    Surface(
                        modifier = Modifier.fillMaxSize(),
                        color = Color(0xFFFFF7F7)
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .verticalScroll(rememberScrollState())
                                .padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Center
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(92.dp)
                                    .background(Color(0xFFFFEBEE), androidx.compose.foundation.shape.CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(text = "!", fontSize = 46.sp, fontWeight = FontWeight.Bold, color = Color(0xFFC62828))
                            }

                            Spacer(modifier = Modifier.height(18.dp))

                            Text(
                                text = "Dangerous Link Blocked",
                                fontSize = 26.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF7F1D1D),
                                textAlign = TextAlign.Center
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            Text(
                                text = "This link matches a risk signal. Going back is the safer choice.",
                                fontSize = 15.sp,
                                lineHeight = 21.sp,
                                color = Color(0xFF6B4B4B),
                                textAlign = TextAlign.Center
                            )

                            Spacer(modifier = Modifier.height(22.dp))

                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = Color.White),
                                elevation = CardDefaults.cardElevation(defaultElevation = 3.dp)
                            ) {
                                Column(modifier = Modifier.padding(18.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text(
                                            text = "Risk level",
                                            fontSize = 13.sp,
                                            color = Color.Gray,
                                            fontWeight = FontWeight.Medium
                                        )
                                        Surface(
                                            color = Color(0xFFFFEBEE),
                                            shape = MaterialTheme.shapes.small
                                        ) {
                                            Text(
                                                text = "High risk",
                                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                                                fontSize = 12.sp,
                                                color = Color(0xFFC62828),
                                                fontWeight = FontWeight.Bold
                                            )
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(14.dp))

                                    Text(
                                        text = url.take(90) + if (url.length > 90) "..." else "",
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .background(Color(0xFFF7F7F7), MaterialTheme.shapes.small)
                                            .padding(12.dp),
                                        fontSize = 12.sp,
                                        lineHeight = 18.sp,
                                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                        color = Color(0xFF424242)
                                    )

                                    Spacer(modifier = Modifier.height(14.dp))

                                    Text(
                                        text = result.explanation,
                                        fontSize = 15.sp,
                                        lineHeight = 22.sp,
                                        color = Color(0xFF333333)
                                    )
                                    if (result.source != null) {
                                        Spacer(modifier = Modifier.height(10.dp))
                                        Surface(
                                            color = Color(0xFFF5F5F5),
                                            shape = MaterialTheme.shapes.small
                                        ) {
                                            Text(
                                                text = "Source: ${result.source}",
                                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                                                fontSize = 12.sp,
                                                color = Color.Gray
                                            )
                                        }
                                    }
                                }
                            }

                            Spacer(modifier = Modifier.height(24.dp))

                            Button(
                                onClick = onGoBack,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(54.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1976D2))
                            ) {
                                Text("Go Back", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            OutlinedButton(
                                onClick = onProceed,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(50.dp),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFC62828))
                            ) {
                                Text(
                                    text = "Open Anyway (At Your Own Risk)",
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                }

                // ── Unknown (should not reach here after Step 2, kept as safety net) ──
                is ApiClient.CheckResult.Unknown -> {
                    Surface(
                        modifier = Modifier.fillMaxSize(),
                        color = Color(0xFFFFFBF0)
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .verticalScroll(rememberScrollState())
                                .padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Center
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(92.dp)
                                    .background(Color(0xFFFFF3D6), androidx.compose.foundation.shape.CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(text = "?", fontSize = 46.sp, fontWeight = FontWeight.Bold, color = Color(0xFFE65100))
                            }

                            Spacer(modifier = Modifier.height(18.dp))

                            Text(
                                text = "Link Needs Review",
                                fontSize = 26.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF7A3E00),
                                textAlign = TextAlign.Center
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            Text(
                                text = "We could not confirm this link as safe yet. If you are not sure, going back is the better choice.",
                                fontSize = 15.sp,
                                lineHeight = 21.sp,
                                color = Color(0xFF6A5436),
                                textAlign = TextAlign.Center
                            )

                            Spacer(modifier = Modifier.height(22.dp))

                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = Color.White),
                                elevation = CardDefaults.cardElevation(defaultElevation = 3.dp)
                            ) {
                                Column(modifier = Modifier.padding(18.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text(
                                            text = "Status",
                                            fontSize = 13.sp,
                                            color = Color.Gray,
                                            fontWeight = FontWeight.Medium
                                        )
                                        Surface(
                                            color = Color(0xFFFFF3D6),
                                            shape = MaterialTheme.shapes.small
                                        ) {
                                            Text(
                                                text = "Unknown",
                                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                                                fontSize = 12.sp,
                                                color = Color(0xFFE65100),
                                                fontWeight = FontWeight.Bold
                                            )
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(14.dp))

                                    Text(
                                        text = url.take(90) + if (url.length > 90) "..." else "",
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .background(Color(0xFFF8F8F8), MaterialTheme.shapes.small)
                                            .padding(12.dp),
                                        fontSize = 12.sp,
                                        lineHeight = 18.sp,
                                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                        color = Color(0xFF424242)
                                    )

                                    Spacer(modifier = Modifier.height(14.dp))

                                    Text(
                                        text = result.explanation,
                                        fontSize = 15.sp,
                                        lineHeight = 22.sp,
                                        color = Color(0xFF333333)
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(24.dp))

                            Button(
                                onClick = onGoBack,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(54.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1976D2))
                            ) {
                                Text("Go Back", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            OutlinedButton(
                                onClick = onProceed,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(50.dp),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFE65100))
                            ) {
                                Text("Open Link", fontSize = 15.sp, fontWeight = FontWeight.Bold)
                            }
                        }
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
