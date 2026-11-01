package io.crossfyre.mobile.approve

import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.UUID
import kotlin.concurrent.thread

/**
 * A stand-in for the platform's approval routes on loopback, holding the rules
 * the phone depends on: an approver counts only once a browser confirmed it, an
 * approval is decided once, and an approve counts only with a signature that
 * verifies over the server's own copy of the digest. The real routes are built on
 * the platform; this is what the phone is tested against until they exist.
 *
 * The rules here are this file's own copies. A test that passes against them
 * shows that the phone speaks the protocol, not that the platform enforces it.
 */
class FakeCloud(private val key: String) : AutoCloseable {
    private val server = ServerSocket(0, 16, InetAddress.getLoopbackAddress())
    val origin = "http://127.0.0.1:${server.localPort}"

    class Approver(val id: String, val code: String, val spki: ByteArray, val deviceName: String, var status: String)
    class Pending(
        val id: String, val summaryJson: String, val digest: String, var status: String, val expiresAt: Instant, var signature: String? = null,
        var launchState: String? = null, var workflowId: String? = null, var workflowStatus: String? = null,
    )
    class Note(val id: String, val title: String, val link: String?, var read: Boolean = false)

    val approvers = mutableListOf<Approver>()
    val approvals = mutableListOf<Pending>()
    val notes = mutableListOf<Note>()
    val routes = mutableListOf<String>()
    var now: Instant = Instant.parse("2026-10-30T09:14:02Z")

    /** A status every `approver/poll` answers with instead of the row's state, while set. */
    @Volatile var pollFails: Int? = null

    /** The same for `approver/revoke`. */
    @Volatile var revokeFails: Int? = null

    /** How long an enrolment code lasts, in seconds, as `approver/start` says. */
    @Volatile var enrolSeconds = 600

    /** The status `logout` answers with, while set, in place of revoking the key. */
    @Volatile var logoutFails: Int? = null

    /** `logout` revoked the account key: every call with it is refused from then on. */
    @Volatile var keyRevoked = false

    /** The fingerprint `approver/start` reports, while set, in place of the key's own: a key changed on the way. */
    @Volatile var startFingerprint: String? = null

    init {
        thread(isDaemon = true) {
            while (!server.isClosed) {
                val sock = runCatching { server.accept() }.getOrNull() ?: break
                sock.use { s ->
                    val input = s.getInputStream().buffered()
                    val first = line(input)
                    if (first.isEmpty()) return@use
                    var length = 0
                    while (true) {
                        val h = line(input)
                        if (h.isEmpty()) break
                        if (h.lowercase().startsWith("content-length:")) length = h.substringAfter(':').trim().toInt()
                    }
                    val body = ByteArray(length).also { var r = 0; while (r < length) { val n = input.read(it, r, length - r); if (n < 0) break; r += n } }
                    val path = first.split(" ")[1]
                    val (status, data) = synchronized(this) { handle(path.removePrefix("/api/v1/cli/"), JSONObject(String(body, Charsets.UTF_8))) }
                    val text = JSONObject().put("status", status).put("message", data.optString("message", "ok"))
                        .put("errors", JSONArray()).put("data", data).toString().toByteArray()
                    val out = s.getOutputStream()
                    out.write("HTTP/1.1 $status X\r\nContent-Type: application/json\r\nContent-Length: ${text.size}\r\nConnection: close\r\n\r\n".toByteArray())
                    out.write(text)
                    out.flush()
                }
            }
        }
    }

    /** The browser page's Confirm, for the signed-in owner of the account. False when there is nothing pending to confirm. */
    @Synchronized fun confirm(code: String): Boolean {
        val a = approvers.firstOrNull { it.code == code && it.status == "pending" } ?: return false
        a.status = "active"
        return true
    }

    /** An agent asks for something that needs a person. */
    @Synchronized fun request(summary: JSONObject): Pending {
        val id = UUID.randomUUID().toString()
        val text = summary.put("id", id).toString()
        val digest = MessageDigest.getInstance("SHA-256").digest(text.toByteArray()).joinToString("") { "%02x".format(it) }
        return Pending(id, text, digest, "pending", now.plusSeconds(600)).also { approvals += it }
    }

    /** The platform launched what an approval let through, and the scan runs. */
    @Synchronized fun launch(a: Pending) {
        a.launchState = "launched"
        a.workflowId = UUID.randomUUID().toString()
        a.workflowStatus = "running"
    }

    /** A notification for the account, newest last. */
    @Synchronized fun notify(title: String, link: String?): Note =
        Note(UUID.randomUUID().toString(), title, link).also { notes += it }

    private fun active(): Approver? = approvers.lastOrNull { it.status == "active" }

    private fun inactive() = 403 to JSONObject().put("approver_inactive", true).put("message", "approver_inactive")

    private fun handle(route: String, b: JSONObject): Pair<Int, JSONObject> {
        routes += route
        if (b.optString("api_key") != key || keyRevoked) return 401 to JSONObject().put("message", "Invalid key")
        return when (route) {
            "approver/start" -> {
                val spki = Base64.getDecoder().decode(b.getString("public_key"))
                if (!Spki.isP256(spki)) return 400 to JSONObject().put("message", "public_key is not a P-256 key")
                val a = Approver(UUID.randomUUID().toString(), "cfe_" + UUID.randomUUID().toString().replace("-", ""), spki, b.getString("device_name"), "pending")
                approvers += a
                200 to JSONObject().put("approver_id", a.id).put("enrol_code", a.code).put("fingerprint", startFingerprint ?: Spki.fingerprint(spki))
                    .put("confirm_url", "https://wrong.example/m/enrol").put("interval", 1).put("expires_in", enrolSeconds)
            }
            "approver/poll" -> pollFails?.let { it to JSONObject().put("message", "Poll refused") }
                ?: approvers.firstOrNull { it.code == b.getString("enrol_code") }
                    ?.let { 200 to JSONObject().put("status", it.status) } ?: (404 to JSONObject().put("message", "Unknown code"))
            "approver/revoke" -> revokeFails?.let { it to JSONObject().put("message", "Revoke failed") } ?: run {
                approvers.firstOrNull { it.id == b.getString("approver_id") }?.status = "revoked"
                200 to JSONObject()
            }
            "approvals/pending" -> {
                val me = approvers.lastOrNull { it.status == "active" }
                200 to JSONObject().put("server_time", now.toString())
                    .put("approver", me?.let { JSONObject().put("id", it.id).put("status", it.status).put("device_name", it.deviceName) } ?: JSONObject.NULL)
                    .put("approvals", JSONArray(approvals.filter { it.status == "pending" }.map {
                        JSONObject().put("id", it.id).put("status", it.status).put("created_at", now.toString())
                            .put("expires_at", it.expiresAt.toString()).put("summary_json", it.summaryJson).put("digest", it.digest)
                    }))
            }
            "approvals/decide" -> decide(b)
            "approvals/history" -> 200 to JSONObject().put("server_time", now.toString())
                .put("approvals", JSONArray(approvals.filter { it.status != "pending" }.map {
                    JSONObject().put("id", it.id).put("status", it.status).put("digest", it.digest)
                        .put("launch_state", it.launchState ?: JSONObject.NULL).put("workflow_id", it.workflowId ?: JSONObject.NULL)
                        .put("workflow_status", it.workflowStatus ?: JSONObject.NULL)
                }))
            "approvals/stop" -> stop(b)
            "inbox/list" -> if (active() == null) inactive() else 200 to JSONObject()
                .put("items", JSONArray(notes.reversed().map {
                    JSONObject().put("id", it.id).put("title", it.title).put("link", it.link ?: JSONObject.NULL).put("read", it.read)
                        .put("category", "approval").put("severity", "warning").put("created_at", now.toString())
                }))
                .put("total", notes.size).put("unread", notes.count { !it.read }).put("page", 1).put("limit", 20)
            "inbox/read" -> if (active() == null) inactive() else {
                val ids = b.optJSONArray("ids")?.let { a -> (0 until a.length()).map { a.getString(it) } }
                val hit = notes.filter { !it.read && (b.optBoolean("all") || ids?.contains(it.id) == true) }
                hit.forEach { it.read = true }
                200 to JSONObject().put("marked", hit.size).put("unread", notes.count { !it.read })
            }
            "logout" -> logoutFails?.let { it to JSONObject().put("message", "Logout failed") } ?: run {
                keyRevoked = true
                200 to JSONObject()
            }
            else -> 404 to JSONObject().put("message", "Not found")
        }
    }

    private fun decide(b: JSONObject): Pair<Int, JSONObject> {
        val a = approvals.firstOrNull { it.id == b.getString("approval_id") } ?: return 404 to JSONObject().put("message", "No such approval")
        if (b.getString("decision") == "deny") {
            if (a.status != "pending") return 409 to JSONObject().put("status", a.status)
            a.status = "denied"
            return 200 to JSONObject().put("status", "denied")
        }
        val dev = approvers.firstOrNull { it.id == b.optString("approver_id") && it.status == "active" }
            ?: return 403 to JSONObject().put("approver_inactive", true).put("message", "approver_inactive")
        if (a.status != "pending") return 409 to JSONObject().put("status", a.status)
        if (!now.isBefore(a.expiresAt)) return 410 to JSONObject().put("status", "expired")
        val bytes = ApprovalProtocol.signingBytes(a.id, "approve", a.digest, b.getLong("signed_at"), dev.id)
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(dev.spki))
        val ok = runCatching {
            Signature.getInstance("SHA256withECDSA").run { initVerify(pub); update(bytes); verify(Base64.getDecoder().decode(b.getString("signature"))) }
        }.getOrDefault(false)
        if (!ok) return 422 to JSONObject().put("message", "bad_signature")
        a.status = "approved"
        a.signature = b.getString("signature")
        return 200 to JSONObject().put("status", "approved")
    }

    /** The platform's order: whose approval, which approver, the signature over "stop", its time, then the scan. */
    private fun stop(b: JSONObject): Pair<Int, JSONObject> {
        val a = approvals.firstOrNull { it.id == b.optString("approval_id") } ?: return 404 to JSONObject().put("message", "No such approval")
        val dev = approvers.firstOrNull { it.id == b.optString("approver_id") && it.status == "active" } ?: return inactive()
        if (!b.has("signed_at") || !b.has("signature")) return 422 to JSONObject().put("message", "bad_signature")
        val at = b.getLong("signed_at")
        val bytes = ApprovalProtocol.signingBytes(a.id, "stop", a.digest, at, dev.id)
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(dev.spki))
        val ok = runCatching {
            Signature.getInstance("SHA256withECDSA").run { initVerify(pub); update(bytes); verify(Base64.getDecoder().decode(b.getString("signature"))) }
        }.getOrDefault(false)
        if (!ok) return 422 to JSONObject().put("message", "bad_signature")
        if (kotlin.math.abs(at - now.epochSecond) > 300) {
            return 422 to JSONObject().put("message", "stale_signature").put("reason", "stale_signature").put("server_time", now.toString())
        }
        if (a.launchState != "launched") return 409 to JSONObject().put("message", "This approval did not launch a scan").put("reason", "not_launched")
        if (a.workflowStatus != "running" && a.workflowStatus != "populating") {
            return 409 to JSONObject().put("message", "That scan is not running").put("reason", "not_running")
        }
        a.workflowStatus = "stopped"
        return 200 to JSONObject().put("id", a.id).put("workflow_id", a.workflowId).put("result", "stopped")
            .put("workflow_status", "stopped").put("operations_cancelled", 2)
    }

    private fun line(input: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0 || c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    override fun close() = server.close()
}
