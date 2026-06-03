package ronyahav.local

import java.net.URI

object LocalUrlLists {

    private val whitelistDomains = setOf(
        "google.com",
        "facebook.com",
        "youtube.com",
        "gmail.com",
        "wikipedia.org",
        "github.com"
    )

    private val blacklistDomains = setOf(
        "bad.test",
        "safe-test-phishing.local",
        "fake-login-test.com",
        "malicious-demo.invalid",
        "bank-security-check.example",
        "verify-account-now.test",
        "phishing-simulation-only.invalid"
    )

    fun check(url: String): LocalUrlResult {
        val host = extractHost(url)
        val matchedWhitelist = whitelistDomains.firstOrNull { host.matchesDomain(it) }
        if (matchedWhitelist != null) {
            return LocalUrlResult.Whitelisted(
                domain = matchedWhitelist,
                description = "Local whitelist match"
            )
        }

        val matchedBlacklist = blacklistDomains.firstOrNull { host.matchesDomain(it) }
        if (matchedBlacklist != null) {
            return LocalUrlResult.Blacklisted(
                domain = matchedBlacklist,
                explanation = "Local blacklist match. This is a safe test domain for checking the warning screen."
            )
        }

        return LocalUrlResult.Unknown
    }

    private fun extractHost(url: String): String {
        val normalizedUrl = if ("://" in url) url else "https://$url"
        return runCatching {
            URI(normalizedUrl).host.orEmpty()
                .lowercase()
                .removePrefix("www.")
                .trimEnd('.')
        }.getOrDefault("")
    }

    private fun String.matchesDomain(domain: String): Boolean {
        return this == domain || endsWith(".$domain")
    }
}

sealed class LocalUrlResult {
    data class Whitelisted(
        val domain: String,
        val description: String
    ) : LocalUrlResult()

    data class Blacklisted(
        val domain: String,
        val explanation: String
    ) : LocalUrlResult()

    data object Unknown : LocalUrlResult()
}
