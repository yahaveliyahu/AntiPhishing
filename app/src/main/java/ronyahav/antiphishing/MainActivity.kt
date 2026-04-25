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
import java.util.Locale
import java.util.concurrent.TimeUnit

// Data class to represent an installed browser
data class BrowserApp(val name: String, val packageName: String)

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

    // Default fallback is Chrome
    val fallbackChrome = "com.android.chrome"
    var selectedBrowserPackage by remember {
        mutableStateOf(prefs.getString("target_browser", fallbackChrome) ?: fallbackChrome)
    }

    // Fetch installed browsers
    val installedBrowsers = remember { getInstalledBrowsers(context) }
    var expanded by remember { mutableStateOf(false) }

    val roleLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
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
                // Save current default browser before taking over
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
                                }
                            }
                        )
                    }

                    Spacer(modifier = Modifier.height(24.dp))
                    Divider(color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.2f))
                    Spacer(modifier = Modifier.height(24.dp))

                    Text("Target Browser (When safe/bypassed):", style = MaterialTheme.typography.labelLarge)
                    Spacer(modifier = Modifier.height(8.dp))

                    // Browser Selection Dropdown
                    ExposedDropdownMenuBox(
                        expanded = expanded,
                        onExpandedChange = { expanded = !expanded }
                    ) {
                        val currentBrowserName = installedBrowsers.find { it.packageName == selectedBrowserPackage }?.name ?: "Chrome (Fallback)"

                        OutlinedTextField(
                            value = currentBrowserName,
                            onValueChange = {},
                            readOnly = true,
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                            modifier = Modifier.menuAnchor()
                        )

                        ExposedDropdownMenu(
                            expanded = expanded,
                            onDismissRequest = { expanded = false }
                        ) {
                            installedBrowsers.forEach { browser ->
                                DropdownMenuItem(
                                    text = { Text(browser.name) },
                                    onClick = {
                                        selectedBrowserPackage = browser.packageName
                                        prefs.edit().putString("target_browser", browser.packageName).apply()
                                        expanded = false
                                    }
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// Helper: Retrieves list of installed browsers
private fun getInstalledBrowsers(context: Context): List<BrowserApp> {
    val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("http://www.google.com"))
    val resolveInfos = context.packageManager.queryIntentActivities(browserIntent, PackageManager.MATCH_ALL)

    val browsers = mutableListOf<BrowserApp>()
    for (info in resolveInfos) {
        val packageName = info.activityInfo.packageName
        if (packageName != context.packageName) { // Exclude our own app
            val appName = info.loadLabel(context.packageManager).toString()
            browsers.add(BrowserApp(appName, packageName))
        }
    }
    // Remove duplicates that might arise from different activities in the same app
    return browsers.distinctBy { it.packageName }
}

// Helper: Tries to find current default browser before we take over
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