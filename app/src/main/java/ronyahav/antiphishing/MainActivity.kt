package ronyahav.antiphishing

import android.Manifest
import android.app.role.RoleManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
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
                    context = this,
                    activity = this
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
fun MainContent(onLanguageToggle: () -> Unit, context: Context, activity: AppCompatActivity) {
    val prefs = context.getSharedPreferences("AntiPhishingPrefs", Context.MODE_PRIVATE)
    var isProtectionActive by remember { mutableStateOf(prefs.getBoolean("is_active", false)) }

    // Launcher for requesting Default Browser Role
    val roleLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        // Check if the user granted the browser role
        val roleManager = context.getSystemService(Context.ROLE_SERVICE) as RoleManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)) {
            Toast.makeText(context, "AntiPhishing is now tracking links!", Toast.LENGTH_SHORT).show()
            toggleSystemState(true, context, prefs)
            isProtectionActive = true
        } else {
            Toast.makeText(context, "Browser role required for protection", Toast.LENGTH_LONG).show()
            isProtectionActive = false
        }
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager = context.getSystemService(Context.ROLE_SERVICE) as RoleManager
            if (!roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)) {
                val intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_BROWSER)
                roleLauncher.launch(intent)
            } else {
                toggleSystemState(true, context, prefs)
                isProtectionActive = true
            }
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

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Active Protection", style = MaterialTheme.typography.titleMedium)
                        Spacer(modifier = Modifier.width(16.dp))
                        Switch(
                            checked = isProtectionActive,
                            onCheckedChange = { isChecked ->
                                if (isChecked) {
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                        val status = ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
                                        if (status != PackageManager.PERMISSION_GRANTED) {
                                            permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                                            return@Switch
                                        }
                                    }
                                    // Request Browser Role if not already held
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                        val roleManager = context.getSystemService(Context.ROLE_SERVICE) as RoleManager
                                        if (!roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)) {
                                            val intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_BROWSER)
                                            roleLauncher.launch(intent)
                                            return@Switch
                                        }
                                    }
                                    toggleSystemState(true, context, prefs)
                                    isProtectionActive = true
                                } else {
                                    toggleSystemState(false, context, prefs)
                                    isProtectionActive = false
                                    Toast.makeText(context, "Protection deactivated. Links will bypass app.", Toast.LENGTH_SHORT).show()
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}

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