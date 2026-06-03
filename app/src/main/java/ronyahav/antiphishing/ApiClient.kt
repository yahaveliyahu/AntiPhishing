package ronyahav.antiphishing

import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * ApiClient
 * Handles HTTP communication with the Flask backend server.
 *
 * Endpoints used:
 *   POST /api/check      → Check a URL from link interception
 *   POST /api/qr/check   → Check a URL decoded from a QR code (same pipeline)
 *   POST /api/qr/report  → Save a QR scan result to MongoDB
 * Request:  { "url": "https://example.com" }
 * Response: { "is_malicious": bool, "confidence": int, "match_type": str,
 *             "source": str|null, "explanation": str }
 *
 * ── Result types extended in Step 2 ─────────────────────────────────────────
 * [Suspicious] and [Safe] are produced by [LexicalAnalyzer] (on-device)
 * when the server returns [Unknown]. They are never returned by the server.
 */
object ApiClient {

    // ── IMPORTANT: Change this to your Flask server IP before testing ─────────
    // Android emulator → http://10.0.2.2:5000
    // Real device on same WiFi → http://YOUR_COMPUTER_IP:5000
    // Production server → https://your-domain.com

//    private const val BASE_URL = "http://10.0.2.2:5000"
//    private const val BASE_URL = "https://clutter-showplace-festival.ngrok-free.app"
    private const val BASE_URL = "http://10.100.102.6:5000"
//    private const val BASE_URL = "http://192.168.222.226:5000"
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

        /** Not found in MongoDB — triggers lexical analysis in [LinkInterceptorActivity] */
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
     * Sends the URL to Flask /api/check and returns a CheckResult.
     * Used by LinkInterceptorActivity for intercepted links.
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
//                setRequestProperty("ngrok-skip-browser-warning", "true")
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

    /**
     * Sends a QR-decoded URL to Flask /api/qr/check and returns a CheckResult.
     * Runs the same pipeline as checkUrl — separate endpoint for clarity and
     * future QR-specific analytics on the server side.
     * Must be called from a background thread.
     */
    fun checkQrUrl(url: String): CheckResult {
        return try {
            val connection = URL("$BASE_URL/api/qr/check")
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

    /**
     * Saves a QR scan result to MongoDB via POST /api/qr/report.
     * Called after every QR scan regardless of result, for history and analytics.
     * Fire-and-forget — failure is silently ignored so it never blocks the UI.
     * Must be called from a background thread.
     */
    fun reportQrScan(url: String, result: CheckResult) {
        try {
            val connection = URL("$BASE_URL/api/qr/report")
                .openConnection() as HttpURLConnection
            connection.apply {
                requestMethod = "POST"
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
            }
            val body = JSONObject().apply {
                put("url", url)
                put("is_malicious", result is CheckResult.Malicious)
                put("confidence", when (result) {
                    is CheckResult.Malicious -> result.confidence
                    is CheckResult.Whitelisted  -> 100
                    is CheckResult.Unknown      -> 0
                    is CheckResult.Error        -> 0
                })
                put("source", when (result) {
                    is CheckResult.Malicious    -> result.source ?: ""
                    is CheckResult.Whitelisted,
                    is CheckResult.Unknown,
                    is CheckResult.Error        -> ""
                })
                put("match_type", when (result) {
                    is CheckResult.Malicious -> result.matchType
                    is CheckResult.Whitelisted -> "whitelist"
                    is CheckResult.Unknown -> "unknown"
                    is CheckResult.Error -> "error"
                })
            }.toString()
            OutputStreamWriter(connection.outputStream).use { it.write(body) }
            connection.responseCode // trigger the request
            connection.disconnect()
        } catch (_: Exception) {
            // Fire-and-forget — reporting failure should never affect the user
        }
    }

    /**
     * Step 3 — Sends the URL and its lexical feature vector to the Flask ML
     * model for final classification.
     *
     * The call site is already written and commented out in LinkInterceptorActivity
     * and QrScannerActivity. Uncomment it there when the ML server is ready.
     *
     * Called from LinkInterceptorActivity and QrScannerActivity after
     * LexicalAnalyzer runs and isObviouslyMalicious is false — i.e. when the
     * lexical analyzer could not make a definitive decision on its own.
     *
     * NOT YET ACTIVE — the Flask /api/score endpoint and the ML model have not
     * been built yet. This function is wired and ready; implement the server
     * side and remove the TODO comment in the callers to activate Step 3.
     *
     * Must be called from a background thread (Dispatchers.IO).
     */

    fun scoreLexical(url: String, features: Map<String, Number>): CheckResult {
        return try {
            val connection = URL("$BASE_URL/api/score")
                .openConnection() as HttpURLConnection

            connection.apply {
                requestMethod = "POST"
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
            }

            val featuresJson = JSONObject()
            features.forEach { (k, v) -> featuresJson.put(k, v) }

            val body = JSONObject()
                .put("url", url)
                .put("features", featuresJson)
                .toString()

            OutputStreamWriter(connection.outputStream).use { it.write(body) }

            val responseCode = connection.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) {
                return CheckResult.Error("ML server returned HTTP $responseCode")
            }

            val responseText = connection.inputStream.bufferedReader().readText()
            connection.disconnect()
            parseResponse(responseText)

        } catch (e: Exception) {
            CheckResult.Error("Could not reach ML server: ${e.message}")
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private fun parseResponse(json: String): CheckResult {
        val obj = JSONObject(json)
        val isMalicious = obj.optBoolean("is_malicious", false)
        val confidence = obj.optInt("confidence", 0)
        val matchType = obj.optString("match_type", "")
        val source = obj.optString("source").takeIf { it.isNotEmpty() && it != "null" }
        val explanation = obj.optString("explanation", "")
        val category = obj.optString("category", "")
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
