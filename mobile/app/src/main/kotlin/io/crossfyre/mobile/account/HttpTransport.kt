package io.crossfyre.mobile.account

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * [Transport] over HttpURLConnection.
 *
 * The Content-Type header is not decoration: the web server's proxy reads the
 * body as JSON only when it is labelled JSON, and answers 400 to the same bytes
 * without it. A 4xx or 5xx is an answer, not a failure, so its body is read from
 * the error stream and handed back like any other; only no answer at all throws.
 */
class HttpTransport(
    private val connectTimeoutMs: Int = 15_000,
    private val readTimeoutMs: Int = 30_000,
) : Transport {

    override fun post(url: String, json: String): Reply {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = connectTimeoutMs
            conn.readTimeout = readTimeoutMs
            conn.useCaches = false
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            val bytes = json.toByteArray(Charsets.UTF_8)
            conn.setFixedLengthStreamingMode(bytes.size)
            conn.outputStream.use { it.write(bytes) }
            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            return Reply(status, body)
        } catch (e: IOException) {
            throw e
        } catch (e: RuntimeException) {
            // A malformed URL or a security exception is as unreachable as a
            // dropped connection from where the person is standing.
            throw IOException(e.message, e)
        } finally {
            conn.disconnect()
        }
    }
}
