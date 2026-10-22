package io.crossfyre.mobile.account

import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

/**
 * The transport against a real HTTP server on loopback.
 *
 * The web server's proxy answers 400 to a JSON body that is not labelled as
 * JSON, so the header is asserted here, where leaving it out would otherwise
 * only show up as every sign-in failing on a phone.
 */
class HttpTransportTest {

    private lateinit var server: ServerSocket
    @Volatile private var seenType: String? = null
    @Volatile private var seenBody: String? = null
    @Volatile private var answer: Pair<Int, String> = 200 to "{}"

    /** A one-request-at-a-time HTTP responder: enough to see what the transport sends. */
    @Before
    fun up() {
        server = ServerSocket(0, 8, InetAddress.getLoopbackAddress())
        thread(isDaemon = true) {
            while (!server.isClosed) {
                val sock = runCatching { server.accept() }.getOrNull() ?: break
                sock.use { s ->
                    val input = s.getInputStream().buffered()
                    val headers = mutableMapOf<String, String>()
                    val first = readLine(input)
                    if (first.isEmpty()) return@use
                    while (true) {
                        val line = readLine(input)
                        if (line.isEmpty()) break
                        val i = line.indexOf(':')
                        if (i > 0) headers[line.substring(0, i).trim().lowercase()] = line.substring(i + 1).trim()
                    }
                    val length = headers["content-length"]?.toIntOrNull() ?: 0
                    val body = ByteArray(length)
                    var read = 0
                    while (read < length) {
                        val n = input.read(body, read, length - read)
                        if (n < 0) break
                        read += n
                    }
                    seenType = headers["content-type"]
                    seenBody = String(body, Charsets.UTF_8)
                    val bytes = answer.second.toByteArray()
                    val out = s.getOutputStream()
                    out.write("HTTP/1.1 ${answer.first} X\r\nContent-Type: application/json\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n".toByteArray())
                    out.write(bytes)
                    out.flush()
                }
            }
        }
    }

    private fun readLine(input: java.io.InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0 || c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    @After
    fun down() = server.close()

    private val base get() = "http://127.0.0.1:${server.localPort}"

    @Test
    fun a_post_is_labelled_json_and_carries_the_body() {
        answer = 200 to """{"status":200,"message":"ok","errors":[],"data":{}}"""
        val r = HttpTransport().post("$base/api/v1/cli/login", """{"identifier":"meera"}""")
        assertEquals(200, r.status)
        assertEquals("application/json", seenType)
        assertEquals("meera", JSONObject(seenBody!!).getString("identifier"))
    }

    @Test
    fun a_refusal_is_an_answer_with_its_body_not_an_exception() {
        answer = 409 to """{"status":409,"message":"Use Google","errors":[],"data":{"use_google":true}}"""
        val r = HttpTransport().post("$base/x", "{}")
        assertEquals(409, r.status)
        assertTrue(r.body, r.body.contains("use_google"))
    }

    @Test(expected = IOException::class)
    fun nothing_listening_is_an_io_failure() {
        val port = server.localPort
        server.close()
        HttpTransport(connectTimeoutMs = 2_000).post("http://127.0.0.1:$port/x", "{}")
    }

    @Test
    fun the_client_names_itself_as_the_mobile_app_when_starting_a_browser_sign_in() {
        answer = 200 to """{"status":200,"message":"ok","errors":[],"data":{"device_code":"cfd_x","interval":3,"expires_in":600}}"""
        val r = AccountApi(base, HttpTransport()).startDeviceLogin(ClientInfo("Pixel 8", "Android 16", "0.2.0"))
        assertTrue(r is Outcome.Ok)
        val info = JSONObject(seenBody!!).getJSONObject("client_info")
        assertEquals("mobile", info.getString("client"))
        assertEquals("Pixel 8", info.getString("hostname"))
    }
}
