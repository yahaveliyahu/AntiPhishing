package ronyahav.antiphishing

import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Language
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.core.os.LocaleListCompat
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import ronyahav.antiphishing.core.database.LinkDao
import ronyahav.antiphishing.core.ui.*
import ronyahav.antiphishing.core.utils.BrowserUtils
import java.util.*
import java.util.concurrent.TimeUnit
import javax.inject.Inject

// Set to true to use local URL lists instead of the Flask server (for development/testing)
const val IS_LOCAL = true

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    @Inject
    lateinit var linkDao: LinkDao

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AntiPhishingTheme {
                MainContent(
                    onLanguageToggle = { toggleLanguage() },
                    onScanQr = {
                        val prefs = getSharedPreferences("AntiPhishingPrefs", MODE_PRIVATE)
                        if (prefs.getBoolean("is_active", false)) {
                            startActivity(Intent(this, QrScannerActivity::class.java))
                        } else {
                            Toast.makeText(
                                this,
                                "Enable protection first to scan QR codes",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    },
                    context = this,
                    linkDao = linkDao
                )
            }
        }
    }

    private fun toggleLanguage() {
        val currentLocales = AppCompatDelegate.getApplicationLocales()
        val currentLanguage = if (!currentLocales.isEmpty) currentLocales[0]?.language else Locale.getDefault().language
        val newLocaleTag = if (currentLanguage == "he") "en" else "he"
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(newLocaleTag))
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainContent(
    onLanguageToggle: () -> Unit,
    onScanQr: () -> Unit,
    context: Context,
    linkDao: LinkDao) {
    val prefs = context.getSharedPreferences("AntiPhishingPrefs", Context.MODE_PRIVATE)
    var isProtectionActive by remember { mutableStateOf(prefs.getBoolean("is_active", false)) }

    // Collecting flows from Room DB for live UI updates
    val startOfDay = Calendar.getInstance().apply { set(Calendar.HOUR_OF_DAY, 0) }.timeInMillis
    val todayCount by linkDao.getTodayScannedCount(startOfDay).collectAsState(initial = 0)
    val blockedCount by linkDao.getBlockedThreatsCount().collectAsState(initial = 0)
    val recentLinks by linkDao.getRecentLinks().collectAsState(initial = emptyList())

    val installedBrowsers = remember { BrowserUtils.getInstalledBrowsers(context) }
    val scope = rememberCoroutineScope()

    val roleLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val roleManager = context.getSystemService(Context.ROLE_SERVICE) as RoleManager
        if (roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)) {
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
                        Icon(Icons.Default.Language, contentDescription = stringResource(R.string.change_language))
                    }
                }
            )
        },
        modifier = Modifier.fillMaxSize()
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(innerPadding).padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            item {
                Spacer(modifier = Modifier.height(16.dp))
                SecurityShield()
                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = if (isProtectionActive) stringResource(R.string.hello_world) else stringResource(R.string.protection_disabled),
                    style = MaterialTheme.typography.headlineSmall,
                    color = if (isProtectionActive) MaterialTheme.colorScheme.primary else Color.Red
                )

                Spacer(modifier = Modifier.height(24.dp))

                // Translated Stats Section
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    StatCard(label = stringResource(R.string.stats_scanned_today), value = todayCount.toString(), color = MaterialTheme.colorScheme.primary, modifier = Modifier.weight(1f))
                    StatCard(label = stringResource(R.string.stats_threats_blocked), value = blockedCount.toString(), color = Color.Red, modifier = Modifier.weight(1f))
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Master Switch
                Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f))) {
                    Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.active_protection), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                        Switch(checked = isProtectionActive, onCheckedChange = { isChecked ->
                            if (isChecked) {
                                val roleManager = context.getSystemService(Context.ROLE_SERVICE) as RoleManager
                                if (!roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)) {
                                    saveCurrentDefaultBrowser(context, prefs)
                                    roleLauncher.launch(roleManager.createRequestRoleIntent(RoleManager.ROLE_BROWSER))
                                    return@Switch
                                }
                            }
                            toggleSystemState(isChecked, context, prefs)
                            isProtectionActive = isChecked
                        })
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
                // QR Scanner button — disabled visually when protection is off
                Button(
                    onClick = onScanQr,
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isProtectionActive)
                            MaterialTheme.colorScheme.primary
                        else
                            Color.Gray
                    )
                ) {
                    Text(
                        text = "📷  Scan QR Code to check",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
                Spacer(modifier = Modifier.height(32.dp))
                // Translated Recent Activity Title
                Text(stringResource(R.string.recent_activity), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, modifier = Modifier.fillMaxWidth())
                Spacer(modifier = Modifier.height(8.dp))
            }

            // Recent Links List
            items(recentLinks) { link ->
                RecentLinkItem(
                    link = link,
                    onDelete = { scope.launch { linkDao.deleteLinkById(link.id) } }
                )
            }

            item {
                Spacer(modifier = Modifier.height(32.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(16.dp))

                TargetBrowserSelector(prefs = prefs, installedBrowsers = installedBrowsers, modifier = Modifier.fillMaxWidth())

                Spacer(modifier = Modifier.height(16.dp))

                // Translated Clear History Button
                TextButton(
                    onClick = { scope.launch { linkDao.clearHistory() } },
                    colors = ButtonDefaults.textButtonColors(contentColor = Color.Gray)
                ) {
                    Icon(Icons.Default.Delete, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.clear_history))
                }
                Spacer(modifier = Modifier.height(32.dp))
            }
        }
    }
}

private fun toggleSystemState(isActive: Boolean, context: Context, prefs: android.content.SharedPreferences) {
    prefs.edit { putBoolean("is_active", isActive) }
    val workManager = WorkManager.getInstance(context)
    if (isActive) {
        val debugWorkRequest = PeriodicWorkRequestBuilder<DebugWorker>(15, TimeUnit.MINUTES).build()
        workManager.enqueueUniquePeriodicWork("DebugAliveWork", androidx.work.ExistingPeriodicWorkPolicy.KEEP, debugWorkRequest)
    } else {
        workManager.cancelUniqueWork("DebugAliveWork")
    }
}

private fun saveCurrentDefaultBrowser(context: Context, prefs: android.content.SharedPreferences) {
    val browserIntent = Intent(Intent.ACTION_VIEW, "http://www.google.com".toUri())
    val resolveInfo = context.packageManager.resolveActivity(browserIntent, PackageManager.MATCH_DEFAULT_ONLY)
    val defaultPackage = resolveInfo?.activityInfo?.packageName
    if (defaultPackage != null && defaultPackage != context.packageName && defaultPackage != "android") {
        prefs.edit { putString("target_browser", defaultPackage) }
    }
}
