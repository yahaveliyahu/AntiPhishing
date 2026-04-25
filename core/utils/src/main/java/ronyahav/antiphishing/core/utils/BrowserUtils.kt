package ronyahav.antiphishing.core.utils

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri

// Data class to represent an installed browser application
data class BrowserApp(val name: String, val packageName: String)

object BrowserUtils {

    // Helper function that retrieves a list of installed web browsers on the device
    fun getInstalledBrowsers(context: Context): List<BrowserApp> {
        val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("http://www.google.com"))
        val resolveInfos = context.packageManager.queryIntentActivities(browserIntent, PackageManager.MATCH_ALL)

        val browsers = mutableListOf<BrowserApp>()
        for (info in resolveInfos) {
            val packageName = info.activityInfo.packageName
            // Exclude our own application from the browser list
            if (packageName != context.packageName) {
                val appName = info.loadLabel(context.packageManager).toString()
                browsers.add(BrowserApp(appName, packageName))
            }
        }

        // Remove duplicate packages that might arise from multiple activities
        return browsers.distinctBy { it.packageName }
    }
}