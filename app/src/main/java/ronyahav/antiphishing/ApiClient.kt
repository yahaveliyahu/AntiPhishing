package ronyahav.antiphishing

import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * ApiClient
 * Handles HTTP communication with the Flask backend server.
 *
 * Endpoint: POST /api/check
 * Request:  { "url": "https://example.com" }
 * Response: { "is_malicious": bool, "confidence": int, "match_type": str,
 *             "source": str|null, "explanation": str }
 */
object ApiClient {

    // ── IMPORTANT: Change this to your Flask server IP before testing ─────────
    // Android emulator → http://10.0.2.2:5000
    // Real device on same WiFi → http://YOUR_COMPUTER_IP:5000  (e.g. http://192.168.1.100:5000)
    // Production server → https://your-domain.com
    private const val BASE_URL = "http://10.0.2.2:5000"
    private const val TIMEOUT_MS = 10_000

    // ── Result types ──────────────────────────────────────────────────────────

    sealed class CheckResult {

        /** Domain is in the whitelist — known safe site (Facebook, Google, Ynet etc.) */
        data class Whitelisted(
            val description: String,   // e.g. "Facebook"
            val category: String       // e.g. "social_media"
        ) : CheckResult()

        /** URL or domain found in malicious blacklist */
        data class Malicious(
            val explanation: String,   // Why it's malicious
            val source: String?,       // e.g. "PhishTank", "URLhaus"
            val confidence: Int,       // 0-100
            val matchType: String      // "url" or "domain"
        ) : CheckResult()

        /** Not found in MongoDB — unknown, needs Phase 2 analysis */
        data class Unknown(
            val explanation: String
        ) : CheckResult()

        /** Server unreachable or network error */
        data class Error(
            val message: String
        ) : CheckResult()
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Sends the URL to Flask and returns a CheckResult.
     * Must be called from a background thread (use coroutines with Dispatchers.IO).
     */
    fun checkUrl(url: String): CheckResult {
        return try {
            val connection = URL("$BASE_URL/api/check")
                .openConnection() as HttpURLConnection

            connection.apply {
                requestMethod = "POST"
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
            }

            val body = JSONObject().put("url", url).toString()
            OutputStreamWriter(connection.outputStream).use { it.write(body) }

            val responseCode = connection.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) {
                return CheckResult.Error("Server returned HTTP $responseCode")
            }

            val responseText = connection.inputStream.bufferedReader().readText()
            connection.disconnect()
            parseResponse(responseText)

        } catch (e: Exception) {
            CheckResult.Error("Could not reach server: ${e.message}")
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private fun parseResponse(json: String): CheckResult {
        val obj         = JSONObject(json)
        val isMalicious = obj.optBoolean("is_malicious", false)
        val confidence  = obj.optInt("confidence", 0)
        val matchType   = obj.optString("match_type", "")
        val source      = obj.optString("source").takeIf { it.isNotEmpty() && it != "null" }
        val explanation = obj.optString("explanation", "")
        val category    = obj.optString("category", "")
        val description = obj.optString("description", "")

        return when {
            matchType == "whitelist" ->
                CheckResult.Whitelisted(description, category)

            isMalicious ->
                CheckResult.Malicious(explanation, source, confidence, matchType)

            else ->
                CheckResult.Unknown(explanation)
        }
    }
}
