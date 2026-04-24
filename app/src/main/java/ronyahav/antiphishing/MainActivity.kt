package ronyahav.antiphishing

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Language
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.os.LocaleListCompat
import ronyahav.antiphishing.core.ui.AntiPhishingTheme
import ronyahav.antiphishing.core.ui.SecurityShield
import java.util.Locale

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Enabling modern edge-to-edge display
        enableEdgeToEdge()

        setContent {
            AntiPhishingTheme {
                MainContent(onLanguageToggle = { toggleLanguage() })
            }
        }
    }

    /**
     * Logic to toggle between Hebrew and English.
     * Uses AppCompatDelegate to persist language selection across restarts.
     */
    private fun toggleLanguage() {
        // Get the current app-specific locales
        val currentLocales = AppCompatDelegate.getApplicationLocales()

        // Check current language: either from app settings or from system default
        val currentLanguage = if (!currentLocales.isEmpty) {
            currentLocales[0]?.language
        } else {
            Locale.getDefault().language
        }

        // Toggle logic
        val newLocaleTag = if (currentLanguage == "he") "en" else "he"

        // Apply the new locale list
        AppCompatDelegate.setApplicationLocales(
            LocaleListCompat.forLanguageTags(newLocaleTag)
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainContent(onLanguageToggle: () -> Unit) {
    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(stringResource(R.string.app_name)) },
                actions = {
                    IconButton(onClick = onLanguageToggle) {
                        Icon(
                            imageVector = Icons.Default.Language,
                            contentDescription = "Change Language"
                        )
                    }
                }
            )
        },
        modifier = Modifier.fillMaxSize()
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentAlignment = Alignment.Center
        ) {
            ElevatedCard(
                modifier = Modifier
                    .padding(24.dp)
                    .fillMaxWidth(),
                shape = MaterialTheme.shapes.extraLarge,
                colors = CardDefaults.elevatedCardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                )
            ) {
                Column(
                    modifier = Modifier.padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    // Animated shield component from core:ui module
                    SecurityShield()

                    Spacer(modifier = Modifier.height(24.dp))

                    Text(
                        text = stringResource(id = R.string.hello_world),
                        style = MaterialTheme.typography.headlineMedium,
                        color = MaterialTheme.colorScheme.primary,
                        textAlign = TextAlign.Center
                    )

                    Text(
                        text = stringResource(id = R.string.welcome_message),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 12.dp)
                    )
                }
            }
        }
    }
}