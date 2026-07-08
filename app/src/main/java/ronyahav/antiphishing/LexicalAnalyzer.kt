package ronyahav.antiphishing

import java.net.URI
import kotlin.math.abs
import kotlin.math.ln

/**
 * LexicalAnalyzer
 *
 * A fully self-contained, offline URL risk-scoring engine.
 * It operates exclusively on the lexical (textual) properties of a URL —
 * no DNS lookups, no network calls — so it works instantly and without internet.
 *
 *── Responsibility ────────────────────────────────────────────────────────────
 * This analyzer does NOT classify URLs as safe or malicious. That decision
 * belongs to the ML model on the Flask server, which has been trained
 * on millions of examples and understands the statistical weight of each
 * feature combination far better than any hand-written threshold can.
 *
 * The ONE exception is [isObviouslyMalicious]: a small set of signals so
 * unambiguous (e.g. javascript: URI, @ symbol) that no legitimate URL ever
 * uses them. These are blocked immediately without waiting for the server.
 *
 * ── How it works ─────────────────────────────────────────────────────────────
 * Every URL is broken into components (scheme, host, path, query, fragment).
 * Then ~25 independent checks are run, each contributing a weighted penalty
 * to a raw score and populating the feature vector. Checks are grouped into:
 *
 *   1. URL Structure & Length       — unusual length, deep paths, query flooding
 *   2. Domain & Subdomain           — excessive subdomains, numeric IPs, typosquatting
 *   3. Suspicious Keywords          — login, verify, account, free, urgent, etc.
 *   4. Character-Level Analysis     — special chars (@, %, -), entropy, alpha ratio
 *   5. TLD & Protocol               — suspicious TLDs, missing HTTPS, data: URIs
 *   6. Advanced Phishing Patterns    — punycode, shorteners, redirectors, homograph, URL-in-query
 *   7. Encoding & Injection Attacks — null bytes, double encoding, backslash, path traversal, IDN TLD
 *
 * ── Output ───────────────────────────────────────────────────────────────────
 * Returns a [LexicalResult] containing:
 *   • isObviouslyMalicious — true ONLY for unambiguous killers; blocks immediately
 *   • flags      — human-readable explanation strings (shown to user / sent to server)
 *   • features   — numeric feature vector forwarded to the Flask ML model
 *
 * ── Integration point ────────────────────────────────────────────────────────
 * Called from [LinkInterceptorActivity] and [QrScannerActivity] when [ApiClient]
 * returns [CheckResult.Unknown] (i.e. the URL was not found in MongoDB):
 *   • isObviouslyMalicious → block immediately; ML model is still called for a
 *     risk percentage, but the explanation/source stays attributed to this analyzer.
 *   • isObviouslySafe      → clear immediately; no ML call needed.
 *   • otherwise            → forward [features] to Flask /api/score and let the
 *     ML model make the final call.
 */
object LexicalAnalyzer {

    // ── Public data types ─────────────────────────────────────────────────────

    data class LexicalResult(
        val isObviouslyMalicious: Boolean,  // True ONLY for unambiguous signals — blocks without ML
        val isObviouslySafe: Boolean,       // True ONLY when zero risk signals triggered — clears without ML
        val flags: List<String>,            // Human-readable explanations for the user
        val features: Map<String, Number>   // Numeric feature vector for the ML server
    )

    // ── Entry point ───────────────────────────────────────────────────────────

    fun analyze(rawUrl: String): LexicalResult {
        val url = rawUrl.trim()

        // Parse URL components; fall back gracefully on malformed input
        val uri = runCatching { URI(url) }.getOrNull()
        val scheme = uri?.scheme?.lowercase() ?: ""
        val host = uri?.host?.lowercase()?.trimEnd('.') ?: extractHostFallback(url)
        val path = uri?.path ?: ""
        val query = uri?.query ?: ""
        val fragment = uri?.fragment ?: ""
        val fullUrl = url.lowercase()

        val flags = mutableListOf<String>()
        var score = 0   // Raw score — used only as a feature sent to the ML model
        var obviousKillers = 0   // Counts signals so unambiguous that no legitimate URL uses them

        // ── 1. URL STRUCTURE & LENGTH ─────────────────────────────────────────

        val urlLength = url.length
        when {
            urlLength > 200 -> { score += 15; flags += "⚠️ Extremely long URL ($urlLength chars) — phishing links often hide destination behind excessive length" }
            urlLength > 100 -> { score += 8;  flags += "⚠️ Unusually long URL ($urlLength chars)" }
            urlLength > 75  -> { score += 3 }
        }

        // Deep directory paths are uncommon on legitimate sites
        val pathDepth = path.split("/").count { it.isNotEmpty() }
        if (pathDepth >= 6) { score += 10; flags += "⚠️ Very deep URL path ($pathDepth levels) — legitimate sites rarely use such deep paths" }
        else if (pathDepth >= 4) { score += 5 }

        // Many query parameters are a classic obfuscation trick
        val queryParamCount = if (query.isNotEmpty()) query.split("&").size else 0
        if (queryParamCount >= 10) { score += 10; flags += "⚠️ Excessive query parameters ($queryParamCount) — often used to confuse security scanners" }
        else if (queryParamCount >= 5) { score += 5 }

        // Presence of URL fragment used for redirection tricks
        if (fragment.isNotEmpty() && fragment.length > 20) { score += 5; flags += "⚠️ Unusually long URL fragment — may be used for redirect manipulation" }

        // ── 2. DOMAIN & HOST ANALYSIS ────────────────────────────────────────

        // Raw IP address instead of domain name
        val isIpAddress = host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))
        if (isIpAddress) { score += 20; flags += "🚨 IP address used instead of domain name — phishing sites frequently avoid registering a domain" }

        val domainParts = host.split(".")
        val tld = domainParts.lastOrNull() ?: ""
        val registrable = if (domainParts.size >= 2) "${domainParts[domainParts.size - 2]}.${domainParts.last()}" else host

        // Excessive subdomains (e.g. secure.login.paypal.verify.evil.com)
        val subdomainCount = (domainParts.size - 2).coerceAtLeast(0)
        when {
            subdomainCount >= 4 -> { score += 20; flags += "🚨 Very many subdomains ($subdomainCount) — classic phishing trick to make URL appear legitimate" }
            subdomainCount >= 3 -> { score += 12; flags += "⚠️ Multiple subdomains ($subdomainCount) — e.g. 'secure.login.bank.evil.com'" }
            subdomainCount == 2 -> { score += 5 }
        }

        // Typosquatting: well-known brand in subdomain but not in registrable domain
        val knownBrands = listOf(
            "paypal", "google", "facebook", "apple", "amazon", "microsoft",
            "netflix", "instagram", "whatsapp", "twitter", "linkedin",
            "ebay", "bank", "bankhapoalim", "bankleumi", "poalim", "leumi",
            "yahoo", "dropbox", "icloud", "wellsfargo", "chase", "barclays"
        )
        val brandInSubdomain = knownBrands.any { brand ->
            host.startsWith("$brand.") || host.contains(".$brand.")
        }
        val brandInRegistrable = knownBrands.any { brand -> registrable.startsWith("$brand.") }

        if (brandInSubdomain && !brandInRegistrable) {
            score += 25
            flags += "🚨 Brand name appears in subdomain only — this is the #1 typosquatting technique (e.g. 'paypal.login.evil.com')"
        }

        // Typosquatting via character substitution (0→o, 1→l, rn→m, etc.)
        val visualSpoofed = checkVisualSpoofing(host, knownBrands)
        if (visualSpoofed != null) { score += 20; flags += "🚨 Domain looks like '$visualSpoofed' but differs by 1–2 characters — typosquatting detected" }

        // Unusually long registrable domain name
        val domainName = domainParts.getOrElse(domainParts.size - 2) { "" }
        when {
            domainName.length > 30 -> { score += 12; flags += "⚠️ Very long domain name (${domainName.length} chars) — legitimate sites have short, memorable names" }
            domainName.length > 20 -> { score += 6 }
        }

        // Hyphens in domain (e.g. secure-paypal-login.com)
        val hyphenCount = host.count { it == '-' }
        when {
            hyphenCount >= 4 -> { score += 15; flags += "🚨 Many hyphens in domain ($hyphenCount) — phishing sites often join multiple words with hyphens" }
            hyphenCount >= 2 -> { score += 8;  flags += "⚠️ Multiple hyphens in domain ($hyphenCount)" }
            hyphenCount == 1 -> { score += 3 }
        }

        // Digits in domain name (not counting TLD)
        val digitCountInDomain = domainName.count { it.isDigit() }
        if (digitCountInDomain >= 3) { score += 8; flags += "⚠️ Many digits in domain name — random-looking domains are often auto-generated by attackers" }

        // ── 3. SUSPICIOUS KEYWORDS ───────────────────────────────────────────

        // High-risk action words — almost always phishing when in a URL
        val highRiskKeywords = listOf(
            "login", "log-in", "signin", "sign-in", "logon", "log-on",
            "verify", "verification", "validate", "account-verify",
            "secure", "security", "update", "confirm", "confirmation",
            "suspend", "suspended", "unlock", "reactivate", "reactivation",
            "billing", "invoice", "payment", "checkout", "reset-password",
            "password-reset", "credential", "webscr", "cmd=", "dispatch="
        )
        val foundHighRisk = highRiskKeywords.filter { fullUrl.contains(it) }
        if (foundHighRisk.size >= 3) {
            score += 20
            flags += "🚨 Multiple high-risk keywords found: ${foundHighRisk.take(4).joinToString(", ")} — strongly associated with credential harvesting"
        } else if (foundHighRisk.size == 2) {
            score += 12
            flags += "⚠️ Suspicious keywords found: ${foundHighRisk.joinToString(", ")}"
        } else if (foundHighRisk.size == 1) {
            score += 6
            flags += "⚠️ Suspicious keyword found: '${foundHighRisk[0]}'"
        }

        // Urgency/social-engineering words
        val urgencyKeywords = listOf(
            "urgent", "immediately", "alert", "warning", "attention",
            "limited", "expire", "expired", "action-required", "act-now",
            "free", "winner", "won", "prize", "gift", "reward",
            "bonus", "congratulations", "claim", "lucky", "selected"
        )
        val foundUrgency = urgencyKeywords.filter { fullUrl.contains(it) }
        if (foundUrgency.size >= 2) {
            score += 12
            flags += "⚠️ Social engineering language in URL: ${foundUrgency.take(3).joinToString(", ")} — used to pressure users into clicking"
        } else if (foundUrgency.size == 1) {
            score += 5
        }

        // Brand names appearing in the path/query (not domain) — classic phishing
        val brandInPathOrQuery = knownBrands.filter { brand ->
            (path.lowercase() + query.lowercase()).contains(brand)
        }
        if (brandInPathOrQuery.isNotEmpty() && !brandInRegistrable) {
            score += 15
            flags += "⚠️ Brand name '${brandInPathOrQuery[0]}' appears in URL path but not in domain — deceptive structure"
        }

        // Fake file extensions in path (e.g. /index.html/secure/login)
        val fakeExtensions = listOf(".php", ".html", ".aspx", ".jsp").count { path.lowercase().contains(it) && path.indexOf(it) < path.lastIndex - it.length }
        if (fakeExtensions > 0) { score += 8; flags += "⚠️ File extension appears in the middle of the path — often used to spoof file type" }

        // ── 4. CHARACTER-LEVEL ANALYSIS ──────────────────────────────────────

        // @ symbol — everything before @ is ignored by browsers (user:pass@evil.com)
        // OBVIOUS KILLER: no legitimate URL ever contains @
        if ('@' in url) { score += 25; obviousKillers++; flags += "🚨 '@' symbol in URL — browsers ignore everything before it, redirecting to a completely different site" }

        // Hidden Unicode characters — invisible to the human eye but change the real URL
        // OBVIOUS KILLER: no legitimate URL ever contains zero-width, direction-control,
        // or soft-hyphen characters. Their only purpose in a URL is deception.
        val dangerousUnicodeRanges = listOf(
            '\u200B'..'\u200D',  // Zero-width space, non-joiner, joiner — completely invisible
            '\u202A'..'\u202E',  // Direction control chars — can visually reverse part of the URL
            '\u2060'..'\u2064',  // Word joiners — invisible separators
            '\uFEFF'..'\uFEFF',  // BOM / zero-width no-break space
            '\u00AD'..'\u00AD'   // Soft hyphen — invisible in most renderers
        )
        val hiddenCharCount = url.count { ch -> dangerousUnicodeRanges.any { ch in it } }
        val hasHiddenChars = hiddenCharCount > 0
        if (hasHiddenChars) {
            score += 50
            obviousKillers++
            flags += "🚨 Hidden Unicode characters detected ($hiddenCharCount found) — invisible characters used to disguise the real URL destination"
        }

        // Double slash in path (not scheme) — redirect trick
        if (path.contains("//")) { score += 10; flags += "⚠️ Double slash in URL path — often used to confuse parsers or create open redirect" }

        // Percent-encoding overuse (legitimate URLs rarely need heavy encoding)
        val percentEncodedCount = url.split("%").size - 1
        when {
            percentEncodedCount >= 15 -> { score += 20; flags += "🚨 Heavy URL encoding ($percentEncodedCount encoded chars) — attackers encode URLs to evade keyword filters" }
            percentEncodedCount >= 6  -> { score += 10; flags += "⚠️ Significant URL encoding ($percentEncodedCount encoded chars)" }
            percentEncodedCount >= 3  -> { score += 5 }
        }

        // Alpha-numeric ratio: phishing domains often have low letter content
        val alphaCount  = host.count { it.isLetter() }
        val digitCount  = host.count { it.isDigit() }
        val alphaRatio  = if (host.isNotEmpty()) alphaCount.toDouble() / host.length else 1.0
        if (alphaRatio < 0.5 && host.length > 5) { score += 12; flags += "⚠️ Low letter ratio in domain (${(alphaRatio * 100).toInt()}%) — random-looking domains suggest auto-generation" }

        // Abnormal special characters in host
        val specialCharsInHost = host.count { !it.isLetterOrDigit() && it != '.' && it != '-' }
        if (specialCharsInHost > 0) { score += 15; flags += "⚠️ Unusual special characters in domain — not allowed in normal domain names" }

        // High Shannon entropy in domain name = random-looking = DGA (Domain Generation Algorithm)
        val entropy = shannonEntropy(domainName)
        when {
            entropy > 4.0 -> { score += 15; flags += "🚨 Domain name appears random/auto-generated (entropy: ${"%.1f".format(entropy)}) — consistent with malware DGA domains" }
            entropy > 3.5 -> { score += 8 }
        }

        // Consecutive consonants — random strings have many (e.g. "xkqvzbn")
        val maxConsecutiveConsonants = longestConsonantRun(domainName)
        if (maxConsecutiveConsonants >= 5) { score += 10; flags += "⚠️ Domain contains long consonant sequence ('$domainName') — looks auto-generated" }

        // Consecutive vowels — made-up words often have unnatural vowel clusters (e.g. "aeiouyx")
        val maxConsecutiveVowels = longestVowelRun(domainName)
        if (maxConsecutiveVowels >= 4) { score += 10; flags += "⚠️ Domain contains long vowel sequence ('$domainName') — looks like a made-up or auto-generated word" }
        else if (maxConsecutiveVowels >= 3) { score += 5 }

        // Misleading dots/dashes that fragment brand names (e.g. pay-pal.com, pay.pal.com)
        val brandFragmented = knownBrands.any { brand ->
            val fragmented = brand.chunked(1).joinToString("[.\\-]")
            Regex(fragmented).containsMatchIn(host)
        }
        if (brandFragmented && !brandInRegistrable) { score += 18; flags += "⚠️ Brand name split with dots or hyphens in domain — a typosquatting trick to evade detection" }

        // ── 5. TLD & PROTOCOL ────────────────────────────────────────────────

        // Dangerous / free / abused TLDs — frequently used in phishing
        val suspiciousTlds = setOf(
            "xyz", "top", "club", "online", "site", "fun", "icu",
            "gq", "ml", "cf", "tk", "ga",   // Free/abused ccTLDs
            "buzz", "rest", "work", "link", "click", "download",
            "zip", "mov",                    // Google TLDs often confused with file extensions
            "pw", "cc", "su", "to", "ws"
        )
        if (tld in suspiciousTlds) { score += 12; flags += "⚠️ Suspicious TLD '.$tld' — this domain extension is frequently used in phishing campaigns" }

        // Numeric TLD (rare but exists, always suspicious)
        if (tld.all { it.isDigit() }) { score += 20; flags += "🚨 Numeric TLD — extremely unusual, nearly always malicious" }

        // No HTTPS
        if (scheme == "http") { score += 8; flags += "⚠️ Unencrypted HTTP connection — legitimate modern sites use HTTPS" }
        // OBVIOUS KILLERS: data: and javascript: are never used in legitimate shared links
        if (scheme == "data") { score += 40; obviousKillers++; flags += "🚨 data: URI — can embed malicious content directly in the link" }
        if (scheme == "javascript") { score += 50; obviousKillers++; flags += "🚨 javascript: URI — executes code directly, never from a link" }
        if (scheme !in listOf("http", "https", "ftp", "ftps", "")) { score += 20; flags += "⚠️ Unusual URL scheme '$scheme'" }

        // Multiple dots in TLD (e.g. .co.uk is fine; .com.example.tk is not)
        if (tld.contains(".")) { score += 10; flags += "⚠️ Compound TLD structure — can be used to disguise the true registrable domain" }

        // Port number in URL (unusual for normal web browsing)
        val port = uri?.port ?: -1
        if (port > 0 && port !in listOf(80, 443, 8080, 8443)) {
            score += 10
            flags += "⚠️ Non-standard port $port — legitimate websites almost never use unusual ports"
        }

        // ── 6. ADVANCED PHISHING PATTERNS ───────────────────────────────────

        // Punycode / Internationalized domain — xn-- prefix means non-Latin characters
        // are encoded to look like a real brand (e.g. xn--pypal-4ve.com looks like paypal.com)
        val isPunycode = host.contains("xn--")
        if (isPunycode) { score += 22; flags += "🚨 Punycode/internationalized domain detected — attackers use non-Latin characters that look identical to real brand names" }

        // Known redirector services abused to hide the real destination URL
        val knownRedirectors = listOf(
            "google.com/url", "google.co", "googleweblight.com",
            "t.co/", "bit.ly/", "tinyurl.com/", "t.ly/", "ow.ly/",
            "rb.gy/", "cutt.ly/", "shorturl.at/", "tiny.cc/",
            "is.gd/", "buff.ly/", "soo.gd/", "bc.vc/"
        )
        val isRedirector = knownRedirectors.any { fullUrl.contains(it) }
        if (isRedirector) { score += 15; flags += "⚠️ Known URL redirector service detected — the real destination is hidden behind a redirect" }

        // URL shortener — completely hides the real destination
        val knownShorteners = listOf(
            "bit.ly", "tinyurl.com", "t.ly", "ow.ly", "rb.gy",
            "cutt.ly", "shorturl.at", "tiny.cc", "is.gd", "buff.ly",
            "soo.gd", "bc.vc", "t.co", "goo.gl", "youtu.be",
            "bl.ink", "snip.ly", "clck.ru", "qr.ae", "po.st"
        )
        val isShortener = knownShorteners.any { host == it || host.endsWith(".$it") }
        if (isShortener) { score += 18; flags += "⚠️ URL shortener detected — the real destination is completely hidden, a common phishing technique" }

        // Repeated brand name in the URL — used to appear more convincing
        // e.g. paypal-paypal-secure-login.com/paypal/verify/paypal
        val brandRepeatCount = knownBrands.maxOfOrNull { brand ->
            val occurrences = fullUrl.split(brand).size - 1
            occurrences
        } ?: 0
        if (brandRepeatCount >= 3) { score += 18; flags += "🚨 Brand name repeated $brandRepeatCount times in URL — used to appear convincing while hiding the real domain" }
        else if (brandRepeatCount == 2) { score += 8 }

        // Excessive dots in the full URL (outside normal TLD structure)
        val dotCount = url.count { it == '.' }
        when {
            dotCount >= 8 -> { score += 15; flags += "🚨 Excessive dots in URL ($dotCount) — deep subdomain nesting used to hide the real domain" }
            dotCount >= 5 -> { score += 8;  flags += "⚠️ Many dots in URL ($dotCount) — suggests suspicious subdomain structure" }
        }

        // Sensitive words used as TLD (e.g. yourbank.secure, apple.support)
        val sensitiveTlds = setOf(
            "secure", "security", "login", "signin", "verify", "account",
            "support", "help", "update", "confirm", "banking", "payment",
            "deals", "offer", "free", "win", "gift", "bonus"
        )
        if (tld in sensitiveTlds) { score += 20; flags += "🚨 Sensitive word used as TLD ('.$tld') — designed to make the URL appear trustworthy" }

        // Full domain name embedded inside the path — redirect disguise
        // e.g. evil.com/https://paypal.com/login  or  evil.com/www.google.com
        val domainInPath = Regex("""(https?://|www\.)[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}""").containsMatchIn(path)
        if (domainInPath) { score += 20; flags += "🚨 A full domain/URL appears inside the URL path — classic redirect attack disguising the real destination" }

        // Excessively long subdomain string (even if count is low)
        // e.g. this-is-definitely-not-a-phishing-site.evil.com
        val subdomainPart = if (domainParts.size > 2) domainParts.dropLast(2).joinToString(".") else ""
        if (subdomainPart.length > 40) { score += 12; flags += "⚠️ Very long subdomain string (${subdomainPart.length} chars) — used to push the real domain out of the visible URL bar" }
        else if (subdomainPart.length > 20) { score += 5 }

        // Mixed character scripts — homograph attack
        // Detects non-ASCII characters in the host which may visually mimic Latin letters
        val hasNonAsciiInHost = host.any { it.code > 127 }
        if (hasNonAsciiInHost) { score += 25; flags += "🚨 Non-ASCII characters detected in domain — homograph attack: foreign letters that look identical to Latin ones" }

        // Full URL embedded inside a query parameter — redirect attack
        // e.g. evil.com/login?redirect=https://paypal.com
        val urlInQuery = Regex("""(https?://|www\.)[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}""").containsMatchIn(query)
        if (urlInQuery) { score += 20; flags += "🚨 A full URL is embedded inside a query parameter — used to disguise the real destination as a redirect" }

        // ── 7. ENCODING, INJECTION & OBFUSCATION ATTACKS ─────────────────────

        // Double extension — hides real file type (e.g. invoice.pdf.apk)
        val dangerousExtensions = listOf(".exe", ".apk", ".bat", ".cmd", ".scr", ".vbs", ".ps1", ".jar", ".msi", ".dmg")
        val safeExtensions      = listOf(".pdf", ".docx", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip")
        val pathLower           = path.lowercase()
        val hasDoubleExtension  = dangerousExtensions.any { danger ->
            safeExtensions.any { safe -> pathLower.contains("$safe$danger") ||
                    (pathLower.contains("$safe.") && pathLower.substringAfterLast("$safe.").contains(danger.removePrefix("."))) }
        }
        if (hasDoubleExtension) { score += 30; obviousKillers++; flags += "🚨 Double file extension detected — a safe-looking extension (e.g. .pdf) hides a dangerous one (e.g. .apk) to trick the user" }

        // OBVIOUS KILLER: Null byte injection
        val hasNullByte = url.contains("%00") || url.contains("\u0000")
        if (hasNullByte) { score += 35; obviousKillers++; flags += "🚨 Null byte detected in URL — used to truncate the URL in some systems and bypass security filters" }

        // OBVIOUS KILLER: Tab / newline / carriage-return injected into URL
        val hasControlChars = url.contains("%09") || url.contains("%0A") || url.contains("%0D") ||
                url.contains('\t')  || url.contains('\n')  || url.contains('\r')
        if (hasControlChars) { score += 30; obviousKillers++; flags += "🚨 Tab or newline character in URL — injected to confuse security scanners while browsers silently ignore them" }

        // Double URL encoding — %25XX decodes to %XX which decodes again.
        // NOT an obvious killer: some legitimate systems (e.g. SAP job listings
        // with parenthetical text in titles, like "(PM)") double-encode
        // characters as a side effect of their own URL generation. Still
        // scored as a signal, but no longer an automatic block — the ML
        // model gets to weigh it alongside everything else instead.
        val hasDoubleEncoding = Regex("%25[0-9A-Fa-f]{2}").containsMatchIn(url)
        if (hasDoubleEncoding) { score += 25; flags += "⚠️ Double URL encoding detected — can indicate an attempt to bypass security filters, but also occurs in some legitimate systems' URL generation" }

        // Backslash in URL — some browsers treat \ as /
        val hasBackslash = url.contains('\\')
        if (hasBackslash) { score += 20; flags += "🚨 Backslash in URL — some browsers treat it as a forward slash, silently navigating to a completely different domain" }

        // OBVIOUS KILLER: Credentials pattern user:password@host
        val hasCredentialsPattern = Regex("""https?://[^@\s]+:[^@\s]+@""").containsMatchIn(url)
        if (hasCredentialsPattern) { score += 30; obviousKillers++; flags += "🚨 Credentials pattern in URL (user:password@host) — the displayed host is fake; browser navigates to the host after the '@'" }

        // URL self-repetition — domain repeated in its own path
        val selfRepeatCount = if (host.length > 4) (path + query).split(host).size - 1 else 0
        if (selfRepeatCount >= 2) { score += 15; flags += "⚠️ URL contains its own domain repeated $selfRepeatCount times in the path — used to overflow length filters" }

        // OBVIOUS KILLER: Unicode normalization attack — circled/Greek letters that normalize to brand names
        val normalizationMap = mapOf(
            'ⓐ' to 'a', 'ⓑ' to 'b', 'ⓒ' to 'c', 'ⓓ' to 'd', 'ⓔ' to 'e',
            'ⓕ' to 'f', 'ⓖ' to 'g', 'ⓗ' to 'h', 'ⓘ' to 'i', 'ⓙ' to 'j',
            'ⓚ' to 'k', 'ⓛ' to 'l', 'ⓜ' to 'm', 'ⓝ' to 'n', 'ⓞ' to 'o',
            'ⓟ' to 'p', 'ⓠ' to 'q', 'ⓡ' to 'r', 'ⓢ' to 's', 'ⓣ' to 't',
            'ⓤ' to 'u', 'ⓥ' to 'v', 'ⓦ' to 'w', 'ⓧ' to 'x', 'ⓨ' to 'y', 'ⓩ' to 'z',
            '\u212B' to 'a', '\u0392' to 'b', '\u03F2' to 'c', '\u0395' to 'e',
            '\u0397' to 'h', '\u0399' to 'i', '\u039A' to 'k', '\u039C' to 'm',
            '\u039D' to 'n', '\u039F' to 'o', '\u03A1' to 'p', '\u03A4' to 't',
            '\u03A5' to 'y', '\u03A7' to 'x'
        )
        val normalizedHost       = host.map { normalizationMap[it] ?: it }.joinToString("")
        val hasNormalizationSpoof = normalizedHost != host && knownBrands.any { brand -> normalizedHost.contains(brand) }
        if (hasNormalizationSpoof) { score += 28; obviousKillers++; flags += "🚨 Unicode normalization attack detected — circled or Greek letters that convert to ASCII brand names" }

        // Path traversal sequences — ../ used to navigate to unintended directories
        val hasPathTraversal = path.contains("../") || path.contains("..\\") ||
                url.contains("%2E%2E%2F") || url.contains("%2E%2E/")
        if (hasPathTraversal) { score += 18; flags += "⚠️ Path traversal sequence (../) detected — used to navigate outside the intended directory and access restricted resources" }

        // Credential or full URL in fragment — single-page app attacks
        val sensitiveFragmentKeywords = listOf("http://", "https://", "www.", "access_token=", "id_token=", "token=", "password=", "passwd=", "pwd=")
        val hasSensitiveFragment      = sensitiveFragmentKeywords.any { fragment.lowercase().contains(it) }
        if (hasSensitiveFragment) { score += 20; flags += "🚨 Sensitive content in URL fragment — credentials or a redirect URL hidden after the # symbol" }

        // Mixed case in domain — evades case-sensitive keyword filters
        val originalHost     = uri?.host ?: extractHostFallback(url)
        val hasMixedCaseHost = originalHost.any { it.isUpperCase() } && originalHost.any { it.isLowerCase() }
        if (hasMixedCaseHost) { score += 8; flags += "⚠️ Mixed uppercase/lowercase in domain — used to evade case-sensitive keyword filters" }

        // OBVIOUS KILLER: Non-ASCII characters in TLD — homograph attack on the TLD itself
        val hasNonAsciiTld = tld.any { it.code > 127 }
        if (hasNonAsciiTld) { score += 25; obviousKillers++; flags += "🚨 Non-ASCII characters in TLD — homograph attack targeting the domain extension itself (e.g. Cyrillic о in .cоm)" }

        // ── Clamp raw score (used only as a feature, not for classification) ────
        val finalScore = score.coerceIn(0, 100)

        // ── Build feature vector for ML server ───────────────────────────────
        val features: Map<String, Number> = mapOf(
            "url_length" to urlLength,
            "path_depth" to pathDepth,
            "query_param_count" to queryParamCount,
            "is_ip_address" to if (isIpAddress) 1 else 0,
            "subdomain_count" to subdomainCount,
            "domain_length" to domainName.length,
            "hyphen_count" to hyphenCount,
            "digit_count_in_domain" to digitCountInDomain,
            "has_at_symbol" to if ('@' in url) 1 else 0,
            "hidden_char_count" to hiddenCharCount,
            "has_double_slash" to if (path.contains("//")) 1 else 0,
            "percent_encoded_count" to percentEncodedCount,
            "alpha_ratio" to alphaRatio,
            "special_chars_in_host" to specialCharsInHost,
            "domain_entropy" to entropy,
            "max_consonant_run" to maxConsecutiveConsonants,
            "max_vowel_run" to maxConsecutiveVowels,
            "high_risk_keyword_count" to foundHighRisk.size,
            "urgency_keyword_count" to foundUrgency.size,
            "brand_in_subdomain" to if (brandInSubdomain && !brandInRegistrable) 1 else 0,
            "brand_in_path" to if (brandInPathOrQuery.isNotEmpty() && !brandInRegistrable) 1 else 0,
            "is_suspicious_tld" to if (tld in suspiciousTlds) 1 else 0,
            "is_https" to if (scheme == "https") 1 else 0,
            "has_non_standard_port" to if (port > 0 && port !in listOf(80, 443, 8080, 8443)) 1 else 0,
            "digit_count_in_host" to digitCount,
            "visual_spoof_detected" to if (visualSpoofed != null) 1 else 0,
            "lexical_risk_score" to finalScore,
            "obvious_killer_count" to obviousKillers,
            "is_punycode" to if (isPunycode) 1 else 0,
            "is_redirector" to if (isRedirector) 1 else 0,
            "is_shortener" to if (isShortener) 1 else 0,
            "brand_repeat_count" to brandRepeatCount,
            "dot_count" to dotCount,
            "sensitive_tld" to if (tld in sensitiveTlds) 1 else 0,
            "domain_in_path" to if (domainInPath) 1 else 0,
            "subdomain_string_length" to subdomainPart.length,
            "has_non_ascii_host" to if (hasNonAsciiInHost) 1 else 0,
            "url_in_query" to if (urlInQuery) 1 else 0,
            "has_double_extension"    to if (hasDoubleExtension) 1 else 0,
            "has_null_byte"           to if (hasNullByte) 1 else 0,
            "has_control_chars"       to if (hasControlChars) 1 else 0,
            "has_double_encoding"     to if (hasDoubleEncoding) 1 else 0,
            "has_backslash"           to if (hasBackslash) 1 else 0,
            "has_credentials_pattern" to if (hasCredentialsPattern) 1 else 0,
            "self_repeat_count"       to selfRepeatCount,
            "has_normalization_spoof" to if (hasNormalizationSpoof) 1 else 0,
            "has_path_traversal"      to if (hasPathTraversal) 1 else 0,
            "has_sensitive_fragment"  to if (hasSensitiveFragment) 1 else 0,
            "has_mixed_case_host"     to if (hasMixedCaseHost) 1 else 0,
            "has_non_ascii_tld"       to if (hasNonAsciiTld) 1 else 0,
            "fake_extension_in_path"  to fakeExtensions,
            "brand_fragmented"        to if (brandFragmented && !brandInRegistrable) 1 else 0
        )

        return LexicalResult(
            isObviouslyMalicious = obviousKillers > 0,
            isObviouslySafe = obviousKillers == 0 && finalScore == 0,
            flags = flags,
            features = features
        )
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Fallback host extraction for malformed URLs that java.net.URI rejects.
     * Handles cases like "http://evil.com/path" where URI constructor throws.
     */
    private fun extractHostFallback(url: String): String {
        return try {
            val afterScheme = url.substringAfter("://")
            afterScheme.substringBefore("/").substringBefore("?").substringBefore("#").lowercase()
        } catch (_: Exception) {
            url.lowercase()
        }
    }

    /**
     * Shannon entropy of a string — higher entropy = more random-looking.
     * Formula: H = -Σ p(c) * log2(p(c))
     */
    private fun shannonEntropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val freq = s.groupingBy { it }.eachCount()
        return freq.values.sumOf { count ->
            val p = count.toDouble() / s.length
            -p * (ln(p) / ln(2.0))
        }
    }

    /**
     * Returns the length of the longest uninterrupted consonant run in a string.
     * High values (≥5) suggest auto-generated (DGA) domain names.
     *
     * Vowels (a,e,i,o,u) reset the run counter.
     * Digits and hyphens are skipped silently — they do not reset the counter,
     * because a digit in the middle of a domain (e.g. "str3ng") should not hide
     * what is effectively a long consonant sequence from the ML model.
     */
    private fun longestConsonantRun(s: String): Int {
        val vowels = setOf('a', 'e', 'i', 'o', 'u')
        var max = 0; var cur = 0
        for (ch in s.lowercase()) {
            when {
                ch.isLetter() && ch !in vowels -> { cur++; if (cur > max) max = cur }
                ch.isLetter() -> cur = 0  // vowel — reset
                // digit or hyphen — skip silently, do not reset
            }
        }
        return max
    }

    /**
     * Returns the length of the longest uninterrupted vowel run in a string.
     * High values (≥3) suggest a made-up or auto-generated domain name,
     * since natural words rarely have more than 2 vowels in a row.
     *
     * Consonants reset the run counter.
     * Digits and hyphens are skipped silently — same reasoning as longestConsonantRun.
     */
    private fun longestVowelRun(s: String): Int {
        val vowels = setOf('a', 'e', 'i', 'o', 'u')
        var max = 0; var cur = 0
        for (ch in s.lowercase()) {
            when {
                ch.isLetter() && ch in vowels -> { cur++; if (cur > max) max = cur }
                ch.isLetter()                 -> cur = 0  // consonant — reset
                // digit or hyphen — skip silently, do not reset
            }
        }
        return max
    }

    /**
     * Checks if a domain looks like a known brand but with 1–2 character substitutions.
     * Covers:
     *   • Numeric swaps: 0→o, 1→l/i, 3→e, 4→a, 5→s
     *   • Double-letter insertion: payppall, googgle
     *   • Single-char insertion / deletion (Levenshtein distance ≤ 1)
     *   • Common bigram swaps: rn→m, cl→d, vv→w
     */
    private fun checkVisualSpoofing(host: String, brands: List<String>): String? {
        val domainBase = host.split(".").getOrElse(host.split(".").size - 2) { host }

        // Normalize the domain by reversing common visual substitutions attackers use
        // to make a fake domain look identical to a real brand at a glance.
        val normalized = domainBase
            // Digit → letter swaps (e.g. paypa1 → paypal, g0ogle → google)
            .replace("0", "o")   // 0 looks like o
            .replace("1", "l")   // 1 looks like l  (e.g. paypa1)
            .replace("1", "i")   // 1 also looks like i (e.g. 1nstagram)
            .replace("3", "e")   // 3 looks like e  (e.g. faceb3ok)
            .replace("4", "a")   // 4 looks like a  (e.g. p4ypal)
            .replace("5", "s")   // 5 looks like s  (e.g. 5ecure)
            .replace("6", "b")   // 6 looks like b  (e.g. 6ank)
            .replace("7", "t")   // 7 looks like t  (e.g. 7witter)
            .replace("9", "g")   // 9 looks like g  (e.g. 9oogle)
            // Special character → letter swaps
            .replace("$", "s")   // $ looks like s  (e.g. $ecure)
            // Capital letter → lowercase lookalikes (confusable in many fonts)
            .replace("I", "l")   // capital I looks like lowercase l (e.g. linkedln → linkedin)
            .replace("O", "o")   // capital O looks like zero
            // Common bigram visual swaps
            .replace("rn", "m")  // rn looks like m  (e.g. arnazon → amazon)
            .replace("cl", "d")  // cl looks like d
            .replace("vv", "w")  // vv looks like w  (e.g. tvvitter → twitter)
            .replace("ii", "n")  // ii looks like n in some fonts

        for (brand in brands) {
            if (normalized == brand) return brand                     // Exact match after normalization
            if (levenshtein(domainBase, brand) == 1) return brand     // One char off
            if (levenshtein(normalized, brand) <= 1) return brand     // One char off after normalization
        }
        return null
    }

    /**
     * Classic iterative Levenshtein distance — avoids recursion to stay efficient on device.
     */
    private fun levenshtein(a: String, b: String): Int {
        if (abs(a.length - b.length) > 3) return 99 // Fast path: very different lengths
        val dp = Array(a.length + 1) { IntArray(b.length + 1) }
        for (i in 0..a.length) dp[i][0] = i
        for (j in 0..b.length) dp[0][j] = j
        for (i in 1..a.length) for (j in 1..b.length) {
            dp[i][j] = if (a[i - 1] == b[j - 1]) dp[i - 1][j - 1]
            else 1 + minOf(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
        }
        return dp[a.length][b.length]
    }
}