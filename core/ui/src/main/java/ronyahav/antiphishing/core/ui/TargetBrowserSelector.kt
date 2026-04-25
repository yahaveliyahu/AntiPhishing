package ronyahav.antiphishing.core.ui

import android.content.SharedPreferences
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import ronyahav.antiphishing.core.utils.BrowserApp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TargetBrowserSelector(
    prefs: SharedPreferences,
    installedBrowsers: List<BrowserApp>,
    modifier: Modifier = Modifier
) {
    val fallbackChrome = "com.android.chrome"

    // Manage current selection state
    var selectedBrowserPackage by remember {
        mutableStateOf(prefs.getString("target_browser", fallbackChrome) ?: fallbackChrome)
    }

    var expanded by remember { mutableStateOf(false) }

    Column(modifier = modifier) {
        Text(
            text = stringResource(id = R.string.target_browser_label),
            style = MaterialTheme.typography.labelLarge
        )
        Spacer(modifier = Modifier.height(8.dp))

        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = !expanded }
        ) {
            // Display localized fallback or the app label
            val currentBrowserName = installedBrowsers.find {
                it.packageName == selectedBrowserPackage
            }?.name ?: stringResource(id = R.string.fallback_browser_name)

            OutlinedTextField(
                value = currentBrowserName,
                onValueChange = {},
                readOnly = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier
                    .menuAnchor()
                    .fillMaxWidth()
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