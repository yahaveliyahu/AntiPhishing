package ronyahav.antiphishing

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Language
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.os.LocaleListCompat
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import ronyahav.antiphishing.core.ui.AntiPhishingTheme
import ronyahav.antiphishing.core.ui.SecurityShield
import java.util.Locale
import java.util.concurrent.TimeUnit

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AntiPhishingTheme {
                MainContent(
                    onLanguageToggle = { toggleLanguage() },
                    context = this
                )
            }
        }
    }

    private fun toggleLanguage() {
        val currentLocales = AppCompatDelegate.getApplicationLocales()
        val currentLanguage = if (!currentLocales.isEmpty) {
            currentLocales[0]?.language
        } else {
            Locale.getDefault().language
        }
        val newLocaleTag = if (currentLanguage == "he") "en" else "he"
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(newLocaleTag))
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainContent(onLanguageToggle: () -> Unit, context: Context) {
    val prefs = context.getSharedPreferences("AntiPhishingPrefs", Context.MODE_PRIVATE)
    var isProtectionActive by remember { mutableStateOf(prefs.getBoolean("is_active", false)) }

    // Permission request launcher for Notifications (Android 13+)
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            toggleSystemState(true, context, prefs)
            isProtectionActive = true
        }
    }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(stringResource(R.string.app_name)) },
                actions = {
                    IconButton(onClick = onLanguageToggle) {
                        Icon(Icons.Default.Language, contentDescription = "Change Language")
                    }
                }
            )
        },
        modifier = Modifier.fillMaxSize()
    ) { innerPadding ->
        Box(modifier = Modifier.fillMaxSize().padding(innerPadding), contentAlignment = Alignment.Center) {
            ElevatedCard(
                modifier = Modifier.padding(24.dp).fillMaxWidth(),
                shape = MaterialTheme.shapes.extraLarge,
                colors = CardDefaults.elevatedCardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                )
            ) {
                Column(
                    modifier = Modifier.padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    SecurityShield()
                    Spacer(modifier = Modifier.height(24.dp))

                    Text(
                        text = if (isProtectionActive) "System Protected" else "Protection Disabled",
                        style = MaterialTheme.typography.headlineMedium,
                        color = if (isProtectionActive) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(32.dp))

                    // The Master Switch
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Active Protection", style = MaterialTheme.typography.titleMedium)
                        Spacer(modifier = Modifier.width(16.dp))
                        Switch(
                            checked = isProtectionActive,
                            onCheckedChange = { isChecked ->
                                if (isChecked && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                    val status = ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
                                    if (status != PackageManager.PERMISSION_GRANTED) {
                                        permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                                        return@Switch
                                    }
                                }
                                toggleSystemState(isChecked, context, prefs)
                                isProtectionActive = isChecked
                            }
                        )
                    }
                }
            }
        }
    }
}

// Helper function to handle saving state and scheduling background work
private fun toggleSystemState(isActive: Boolean, context: Context, prefs: android.content.SharedPreferences) {
    prefs.edit().putBoolean("is_active", isActive).apply()

    val workManager = WorkManager.getInstance(context)
    if (isActive) {
        val debugWorkRequest = PeriodicWorkRequestBuilder<DebugWorker>(15, TimeUnit.MINUTES).build()
        workManager.enqueueUniquePeriodicWork(
            "DebugAliveWork",
            androidx.work.ExistingPeriodicWorkPolicy.KEEP,
            debugWorkRequest
        )
    } else {
        workManager.cancelUniqueWork("DebugAliveWork")
    }
}