package ronyahav.antiphishing

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.OptIn
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.lifecycleScope
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ronyahav.antiphishing.core.database.LinkDao
import ronyahav.antiphishing.core.database.ScannedLink
import ronyahav.antiphishing.core.ui.AntiPhishingTheme
import ronyahav.local.LocalUrlLists
import ronyahav.local.LocalUrlResult
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.inject.Inject

@AndroidEntryPoint
class QrScannerActivity : ComponentActivity() {

    @Inject
    lateinit var linkDao: LinkDao

    private lateinit var cameraExecutor: ExecutorService

    // Prevents processing multiple QR frames after the first valid scan
    private var scanHandled = false

    private val requestPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) showScannerScreen()
            else {
                Toast.makeText(this, "Camera permission is required to scan QR codes", Toast.LENGTH_LONG).show()
                finish()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        cameraExecutor = Executors.newSingleThreadExecutor()

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            == PackageManager.PERMISSION_GRANTED
        ) {
            showScannerScreen()
        } else {
            requestPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun showScannerScreen() {
        setContent {
            AntiPhishingTheme {
                QrScannerScreen(
                    cameraExecutor = cameraExecutor,
                    onClose = { finish() },
                    onQrDetected = { url ->
                        if (!scanHandled) {
                            scanHandled = true
                            onQrDetected(url)
                        }
                    }
                )
            }
        }
    }

    /**
     * Called once when a QR code containing a URL is detected.
     * Runs the full check pipeline and saves to both local DB and MongoDB.
     */
    private fun onQrDetected(url: String) {
        setContent {
            AntiPhishingTheme {
                QrCheckingScreen(url = url)
            }
        }

        lifecycleScope.launch {
            // Step 1: Check against local lists (IS_LOCAL=true) or Flask server
            val serverResult: ApiClient.CheckResult = if (IS_LOCAL) {
                checkLocalLists(url)
            } else {
                withContext(Dispatchers.IO) {
                    ApiClient.checkQrUrl(url)
                }
            }

            // Step 2: Lexical analysis for Unknown results
            val finalResult: ApiClient.CheckResult =
                if (serverResult is ApiClient.CheckResult.Unknown) {
                    val lexical = withContext(Dispatchers.Default) {
                        LexicalAnalyzer.analyze(url)
                    }
                    if (lexical.isObviouslyMalicious) {
                        ApiClient.CheckResult.Malicious(
                            explanation = lexical.flags.take(3).joinToString("\n"),
                            source = "Lexical Analysis",
                            confidence = 95,
                            matchType = "lexical"
                        )
                    } else {
                        // Step 3: Forward feature vector to Flask ML server
                        // TODO: uncomment when ML model is ready
//                        withContext(Dispatchers.IO) {
//                            ApiClient.scoreLexical(url, lexical.features)
//                        }
                        val riskScore = lexical.features["lexical_risk_score"] ?: 0
                        ApiClient.CheckResult.Unknown(
                            "Lexical analysis complete (score: $riskScore). " +
                                    "Step 3 ML model not built yet — cannot make final decision."
                        )
                    }
                } else {
                    serverResult
                }

            // Save to local Room DB immediately
            saveToLocalDb(url, finalResult)

            // Show toast when QR code is confirmed safe (whitelisted)
            if (finalResult is ApiClient.CheckResult.Whitelisted) {
                Toast.makeText(
                    this@QrScannerActivity,
                    "The QR code you scanned is not malicious. You are safe 😊",
                    Toast.LENGTH_SHORT
                ).show()
            }

            // Save to MongoDB via Flask when running against real server
            if (!IS_LOCAL) {
                launch(Dispatchers.IO) {
                    ApiClient.reportQrScan(url, finalResult)
                }
            }

            // Show result screen
            setContent {
                AntiPhishingTheme {
                    val prefs = getSharedPreferences("AntiPhishingPrefs", MODE_PRIVATE)
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
            is LocalUrlResult.Unknown -> ApiClient.CheckResult.Unknown(
                "No match in local whitelist or blacklist."
            )
        }
    }

    private suspend fun saveToLocalDb(url: String, result: ApiClient.CheckResult) {
        val linkEntry = ScannedLink(
            url = url,
            isSuspicious = result is ApiClient.CheckResult.Malicious,
            riskScore = when (result) {
                is ApiClient.CheckResult.Whitelisted -> 0
                is ApiClient.CheckResult.Malicious   -> result.confidence
                is ApiClient.CheckResult.Unknown     -> 50
                is ApiClient.CheckResult.Error       -> 50
            },
            threatType = when (result) {
                is ApiClient.CheckResult.Malicious   -> result.source
                is ApiClient.CheckResult.Whitelisted,
                is ApiClient.CheckResult.Unknown,
                is ApiClient.CheckResult.Error       -> null
            }
        )
        linkDao.insertAndTrim(linkEntry)
    }

    private fun forwardToBrowser(url: String, prefs: android.content.SharedPreferences) {
        val browserIntent = Intent(Intent.ACTION_VIEW, url.toUri())
        var targetPackage = prefs.getString("target_browser", "com.android.chrome") ?: "com.android.chrome"
        val isInstalled = try {
            packageManager.getPackageInfo(targetPackage, 0); true
        } catch (_: PackageManager.NameNotFoundException) { false }
        if (!isInstalled) targetPackage = "com.android.chrome"
        browserIntent.`package` = targetPackage
        browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            startActivity(browserIntent)
        } catch (_: Exception) {
            browserIntent.`package` = null
            startActivity(browserIntent)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }
}

// ── Composables ──────────────────────────────────────────────────────────────

@OptIn(ExperimentalGetImage::class)
@Composable
fun QrScannerScreen(
    cameraExecutor: ExecutorService,
    onClose: () -> Unit,
    onQrDetected: (String) -> Unit
) {
    val lifecycleOwner = LocalLifecycleOwner.current

    Box(modifier = Modifier.fillMaxSize()) {

        // Camera preview — PreviewView is created here and wired directly to CameraX
        AndroidView(
            factory = { ctx ->
                val previewView = PreviewView(ctx)

                val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                cameraProviderFuture.addListener({
                    val cameraProvider = cameraProviderFuture.get()

                    @Suppress("UsePropertyAccessSyntax")
                    val preview = Preview.Builder().build().also {
                        it.setSurfaceProvider(previewView.surfaceProvider)
                    }

                    val imageAnalysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()

                    imageAnalysis.setAnalyzer(cameraExecutor) { imageProxy ->
                        val mediaImage = imageProxy.image
                        if (mediaImage != null) {
                            val image = InputImage.fromMediaImage(
                                mediaImage,
                                imageProxy.imageInfo.rotationDegrees
                            )
                            val scanner = BarcodeScanning.getClient()
                            scanner.process(image)
                                .addOnSuccessListener { barcodes ->
                                    for (barcode in barcodes) {
                                        if (barcode.valueType == Barcode.TYPE_URL ||
                                            barcode.valueType == Barcode.TYPE_TEXT
                                        ) {
                                            val rawValue = barcode.rawValue ?: continue
                                            val url = extractUrlFromText(rawValue) ?: continue
                                            onQrDetected(url)
                                            break
                                        }
                                    }
                                }
                                .addOnCompleteListener { imageProxy.close() }
                        } else {
                            imageProxy.close()
                        }
                    }

                    try {
                        cameraProvider.unbindAll()
                        cameraProvider.bindToLifecycle(
                            lifecycleOwner,
                            CameraSelector.DEFAULT_BACK_CAMERA,
                            preview,
                            imageAnalysis
                        )
                    } catch (e: Exception) {
                        Toast.makeText(ctx, "Failed to start camera: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }, ContextCompat.getMainExecutor(ctx))

                previewView
            },
            modifier = Modifier.fillMaxSize()
        )

        // Overlay on top of the camera preview
        Column(
            modifier = Modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Scan QR Code",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold
                )
                IconButton(onClick = onClose) {
                    Icon(Icons.Default.Close, contentDescription = "Close", tint = Color.White)
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            Text(
                text = "Point your camera at a QR code",
                color = Color.White,
                fontSize = 14.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(bottom = 48.dp)
            )
        }
    }
}

@Composable
fun QrCheckingScreen(url: String) {
    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            CircularProgressIndicator(modifier = Modifier.size(64.dp), strokeWidth = 4.dp)
            Spacer(modifier = Modifier.height(24.dp))
            Text(
                text = "🔍 Checking QR code safety...",
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

// Standalone helper — called from inside the Composable where the class scope is unavailable
private fun extractUrlFromText(text: String): String? {
    if (text.startsWith("http://") || text.startsWith("https://")) return text
    val urlPattern = Regex("""https?://\S+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/\S*)?""")
    val raw = urlPattern.find(text)?.value?.trimEnd('.', ',', ';', ')', ']', '}') ?: return null
    return if (raw.startsWith("http://") || raw.startsWith("https://")) raw else "https://$raw"
}