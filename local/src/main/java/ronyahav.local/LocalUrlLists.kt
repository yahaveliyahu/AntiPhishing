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

    private val blacklistDomains = mapOf(
        "bad.test" to "Flagged as a known-malicious domain — not associated with any legitimate registered business or service.",
        "safe-test-phishing.local" to "Domain name itself contains the word \"phishing\" and does not correspond to a registered business — consistent with disposable attack infrastructure.",
        "fake-login-test.com" to "Domain name combines \"fake\" and \"login\" — consistent with a credential-harvesting page impersonating a legitimate sign-in portal.",
        "malicious-demo.invalid" to "Domain name explicitly signals malicious intent and does not correspond to any legitimate registered service.",
        "bank-security-check.example" to "Domain combines banking and security-alert language (\"bank\", \"security\", \"check\") — a classic pattern used to impersonate a financial institution's security notices.",
        "phishing-simulation-only.invalid" to "Domain name explicitly references phishing and does not correspond to any real registered business."
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

        val matchedBlacklist = blacklistDomains.keys.firstOrNull { host.matchesDomain(it) }
        if (matchedBlacklist != null) {
            return LocalUrlResult.Blacklisted(
                domain = matchedBlacklist,
                explanation = blacklistDomains.getValue(matchedBlacklist)
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
