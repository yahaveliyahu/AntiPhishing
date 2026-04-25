package ronyahav.antiphishing

import android.Manifest
import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
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
import ronyahav.antiphishing.core.ui.TargetBrowserSelector
import ronyahav.antiphishing.core.utils.BrowserUtils
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

    val installedBrowsers = remember { BrowserUtils.getInstalledBrowsers(context) }

    // Logic for tracking link successes
    val successMsg = stringResource(id = R.string.tracking_active)
    val failureMsg = stringResource(id = R.string.browser_role_required)
    val deactivatedMsg = stringResource(id = R.string.protection_deactivated)

    val roleLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        val roleManager = context.getSystemService(Context.ROLE_SERVICE) as RoleManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)) {
            Toast.makeText(context, successMsg, Toast.LENGTH_SHORT).show()
            toggleSystemState(true, context, prefs)
            isProtectionActive = true
        } else {
            Toast.makeText(context, failureMsg, Toast.LENGTH_LONG).show()
            isProtectionActive = false
        }
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager = context.getSystemService(Context.ROLE_SERVICE) as RoleManager
            if (!roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)) {
                saveCurrentDefaultBrowser(context, prefs)
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
                        Icon(Icons.Default.Language, contentDescription = stringResource(id = R.string.change_language))
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
                        text = if (isProtectionActive) stringResource(id = R.string.hello_world) else stringResource(id = R.string.protection_disabled),
                        style = MaterialTheme.typography.headlineMedium,
                        color = if (isProtectionActive) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(32.dp))

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(id = R.string.active_protection), style = MaterialTheme.typography.titleMedium)
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
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                        val roleManager = context.getSystemService(Context.ROLE_SERVICE) as RoleManager
                                        if (!roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)) {
                                            saveCurrentDefaultBrowser(context, prefs)
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
                                    Toast.makeText(context, deactivatedMsg, Toast.LENGTH_SHORT).show()
                                }
                            }
                        )
                    }

                    Spacer(modifier = Modifier.height(24.dp))
                    HorizontalDivider(color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.2f))
                    Spacer(modifier = Modifier.height(24.dp))

                    TargetBrowserSelector(
                        prefs = prefs,
                        installedBrowsers = installedBrowsers,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }
    }
}

private fun saveCurrentDefaultBrowser(context: Context, prefs: android.content.SharedPreferences) {
    val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("http://www.google.com"))
    val resolveInfo = context.packageManager.resolveActivity(browserIntent, PackageManager.MATCH_DEFAULT_ONLY)

    val defaultPackage = resolveInfo?.activityInfo?.packageName
    if (defaultPackage != null && defaultPackage != context.packageName && defaultPackage != "android") {
        prefs.edit().putString("target_browser", defaultPackage).apply()
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