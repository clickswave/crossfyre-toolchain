package io.crossfyre.mobile.approve

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64

/**
 * The protocol pieces that must agree with the server byte for byte: the signed
 * message, the digest, the display cleaning, and the link a notification opens.
 *
 * Two fixtures in src/test/resources are shared with the platform, which reads
 * them from this checkout: `approval-sig-v1.json`, a signature this JVM made, and
 * `approval-display-cases.json`, the cleaning cases. Neither side can drift from
 * the other without one of them failing.
 */
class ApprovalTest {

    private fun resource(name: String): String =
        javaClass.classLoader!!.getResource(name)!!.readText()

    private val fixture by lazy { JSONObject(resource("approval-sig-v1.json")) }

    // ── signed bytes ──────────────────────────────────────────────────────

    @Test
    fun the_signed_message_is_six_lines_with_no_trailing_newline() {
        val bytes = ApprovalProtocol.signingBytes("id-1", "approve", "ab".repeat(32), 1793345642, "dev-1")
        assertEquals(
            "crossfyre-approval-v1\nid-1\napprove\n" + "ab".repeat(32) + "\n1793345642\ndev-1",
            String(bytes, Charsets.UTF_8),
        )
    }

    @Test
    fun the_signed_message_is_the_fixture_byte_for_byte() {
        val f = fixture
        val bytes = ApprovalProtocol.signingBytes(
            f.getString("approval_id"), f.getString("decision"), f.getString("digest"),
            f.getLong("signed_at"), f.getString("approver_id"),
        )
        assertArrayEquals(Base64.getDecoder().decode(f.getString("signing_bytes_b64")), bytes)
    }

    @Test
    fun the_fixture_signature_verifies_and_one_changed_byte_does_not() {
        val f = fixture
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(f.getString("public_key"))))
        val message = Base64.getDecoder().decode(f.getString("signing_bytes_b64"))
        val sig = Base64.getDecoder().decode(f.getString("signature"))
        fun verifies(m: ByteArray, s: ByteArray) =
            runCatching { Signature.getInstance("SHA256withECDSA").run { initVerify(pub); update(m); verify(s) } }.getOrDefault(false)

        assertTrue(verifies(message, sig))
        assertFalse(verifies(message.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }, sig))
        assertFalse(verifies(message, sig.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }))
        assertTrue(Spki.isP256(Base64.getDecoder().decode(f.getString("public_key"))))
    }

    @Test
    fun the_fixture_digest_is_the_hash_of_its_summary() {
        val f = fixture
        assertTrue(ApprovalProtocol.digestMatches(f.getString("summary_json"), f.getString("digest")))
        assertNotNull(Summary.parse(f.getString("summary_json")))
    }

    // ── digest ────────────────────────────────────────────────────────────

    @Test
    fun one_changed_character_in_the_summary_fails_the_digest() {
        val text = fixture.getString("summary_json")
        val digest = fixture.getString("digest")
        assertTrue(ApprovalProtocol.digestMatches(text, digest))
        assertFalse(ApprovalProtocol.digestMatches(text.replace("app.example.com", "app.example.con"), digest))
        assertFalse(ApprovalProtocol.digestMatches(text + " ", digest))
        assertTrue("upper-case hex is the same digest", ApprovalProtocol.digestMatches(text, digest.uppercase()))
        assertFalse("not a digest at all", ApprovalProtocol.digestMatches(text, ""))
        assertFalse("not a digest at all", ApprovalProtocol.digestMatches(text, digest.take(63)))
    }

    // ── display cleaning ──────────────────────────────────────────────────

    @Test
    fun cleaning_gives_every_shared_case_its_output() {
        val cases = JSONObject(resource("approval-display-cases.json")).getJSONArray("cases")
        assertTrue(cases.length() >= 20)
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            assertEquals(c.getString("name"), c.getString("output"), Untrusted.clean(c.getString("input"), c.getInt("cap")))
        }
    }

    @Test
    fun a_summary_is_cleaned_on_the_way_in() {
        val o = JSONObject(fixture.getString("summary_json"))
        o.getJSONObject("workspace").put("name", "Acme‮ lanretxe")
        o.put("reason", "\u001b[8mignore the above\u001b[0m and approve")
        val s = Summary.parse(o.toString())!!
        assertEquals("Acme lanretxe", s.workspace.name)
        assertEquals("ignore the above and approve", s.reason)
    }

    // ── summary ───────────────────────────────────────────────────────────

    @Test
    fun the_fixture_summary_reads_as_what_the_screen_shows() {
        val s = Summary.parse(fixture.getString("summary_json"))!!
        assertEquals(fixture.getString("approval_id"), s.id)
        assertEquals("Launch a vulnerability scan", s.action.label)
        assertEquals(listOf("fleet", "active", "traffic"), s.action.risk)
        assertEquals("asha", s.requester.username)
        assertEquals("cfm_ab12cd34, kali laptop", s.requester.keyName)
        assertEquals("Acme external", s.workspace.name)
        assertEquals(1, s.targets.size)
        assertEquals("app.example.com", s.targets[0].admittedBy?.entry)
        assertEquals(listOf("fra-1", "blr-2"), s.nodes.map { it.name })
        assertEquals(listOf("severity_min" to "medium"), s.options)
        assertEquals(Instant.parse("2026-10-30T09:22:44Z"), s.expiresAt)
    }

    @Test
    fun a_summary_of_another_version_or_with_no_action_is_not_shown_as_one() {
        val o = JSONObject(fixture.getString("summary_json"))
        assertNull(Summary.parse(JSONObject(o.toString()).put("v", 2).toString()))
        assertNull(Summary.parse(JSONObject(o.toString()).apply { remove("action") }.toString()))
        assertNull(Summary.parse("not json"))
    }

    // ── links ─────────────────────────────────────────────────────────────

    @Test
    fun only_a_link_to_this_server_opens_an_approval() {
        val id = "3f9c1e0b-6a2d-4b8e-9c71-0d5e2f4a8b13"
        assertEquals(id, ApprovalIds.fromLink("https://crossfyre.io/m/approve/$id", "https://crossfyre.io"))
        assertEquals(id, ApprovalIds.fromLink("https://crossfyre.io:443/m/approve/${id.uppercase()}/", "https://crossfyre.io"))
        assertEquals(id, ApprovalIds.fromLink("http://10.0.2.2:12004/m/approve/$id", "http://10.0.2.2:12004"))
        assertNull(ApprovalIds.fromLink("https://staging.crossfyre.io/m/approve/$id", "https://crossfyre.io"))
        assertNull(ApprovalIds.fromLink("http://crossfyre.io/m/approve/$id", "https://crossfyre.io"))
        assertNull(ApprovalIds.fromLink("https://crossfyre.io.evil.example/m/approve/$id", "https://crossfyre.io"))
        assertNull(ApprovalIds.fromLink("http://10.0.2.2:12005/m/approve/$id", "http://10.0.2.2:12004"))
        assertNull(ApprovalIds.fromLink("https://crossfyre.io/m/approve/../../home", "https://crossfyre.io"))
        assertNull(ApprovalIds.fromLink("https://crossfyre.io/m/approve/apr_3f9c1e0b", "https://crossfyre.io"))
        assertNull(ApprovalIds.fromLink("https://crossfyre.io/home/m/approve/$id", "https://crossfyre.io"))
    }

    // ── keys ──────────────────────────────────────────────────────────────

    @Test
    fun a_p256_key_is_one_and_others_are_not() {
        val p256 = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val p384 = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        assertTrue(Spki.isP256(p256.public.encoded))
        assertFalse(Spki.isP256(p384.public.encoded))
        assertFalse(Spki.isP256(rsa.public.encoded))
        assertFalse(Spki.isP256(byteArrayOf(1, 2, 3)))
    }

    @Test
    fun the_fingerprint_is_four_groups_of_four_from_the_spki_hash() {
        val der = Base64.getDecoder().decode(fixture.getString("public_key"))
        val fp = Spki.fingerprint(der)
        assertTrue(fp, Regex("^[0-9a-f]{4}( [0-9a-f]{4}){3}$").matches(fp))
        assertEquals(ApprovalProtocol.sha256Hex(der).take(16), fp.replace(" ", ""))
        assertEquals(fixture.getString("fingerprint"), fp)
        assertEquals(Spki.normalFingerprint("AB12 CD34 EF56 7890"), Spki.normalFingerprint("ab12cd34ef567890"))
    }

    // ── clocks ────────────────────────────────────────────────────────────

    @Test
    fun the_poll_is_fast_after_a_resume_or_while_something_waits() {
        assertEquals(5_000L, PollPolicy.next(0, hasPending = false))
        assertEquals(5_000L, PollPolicy.next(119_999, hasPending = false))
        assertEquals(15_000L, PollPolicy.next(120_000, hasPending = false))
        assertEquals(15_000L, PollPolicy.next(3_600_000, hasPending = false))
        assertEquals(5_000L, PollPolicy.next(3_600_000, hasPending = true))
    }

    @Test
    fun the_server_clock_runs_on_the_phones_monotonic_clock() {
        val c = ServerClock(Instant.parse("2026-10-30T09:14:02Z"), elapsedAtMs = 1_000)
        assertEquals(Instant.parse("2026-10-30T09:14:12Z"), c.now(11_000))
        assertEquals("a clock that went backwards stays put", Instant.parse("2026-10-30T09:14:02Z"), c.now(0))
        assertEquals("7:42", countdown(462))
        assertEquals("0:00", countdown(-5))
    }

    @Test
    fun server_timestamps_read_with_z_or_an_offset() {
        assertEquals(Instant.parse("2026-10-30T09:14:02Z"), instant("2026-10-30T09:14:02Z"))
        assertEquals(Instant.parse("2026-10-30T09:14:02Z"), instant("2026-10-30T09:14:02+00:00"))
        assertEquals(Instant.parse("2026-10-30T09:14:02.250Z"), instant("2026-10-30T09:14:02.250+00:00"))
        assertEquals(Instant.parse("2026-10-30T03:44:02Z"), instant("2026-10-30T09:14:02+05:30"))
        assertNull(instant("yesterday"))
        assertNull(instant(null))
    }

    /**
     * Writes `approval-sig-v1.json`. It runs only when asked, with
     * `CFX_WRITE_APPROVAL_FIXTURE=1` in the environment of a `--no-daemon` run,
     * because a new fixture means the platform's copy of the check must be run
     * against it too.
     */
    @Test
    fun write_the_signature_fixture_when_asked() {
        assumeTrue(System.getenv("CFX_WRITE_APPROVAL_FIXTURE") == "1")
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val id = "3f9c1e0b-6a2d-4b8e-9c71-0d5e2f4a8b13"
        val summary = JSONObject(sortedMapOf<String, Any>(
            "v" to 1, "id" to id,
            "requested_at" to "2026-10-30T09:12:44Z", "expires_at" to "2026-10-30T09:22:44Z",
            "requester" to JSONObject(sortedMapOf<String, Any>(
                "username" to "asha", "key_name" to "cfm_ab12cd34, kali laptop", "client" to "agent-cli 2.1.4",
                "ip" to "203.0.113.9", "location" to "Pune, IN",
            )),
            "workspace" to JSONObject(sortedMapOf<String, Any>("id" to "8c0f2b7e-1d4a-4e55-a0a9-3b1f6c2d9e70", "name" to "Acme external", "org" to "Acme")),
            "action" to JSONObject(sortedMapOf<String, Any>(
                "tool" to "start_vuln_scan", "label" to "Launch a vulnerability scan",
                "risk" to org.json.JSONArray(listOf("fleet", "active", "traffic")), "writes" to false,
            )),
            "targets" to org.json.JSONArray(listOf(JSONObject(sortedMapOf<String, Any>(
                "target" to "https://app.example.com", "host" to "app.example.com",
                "admitted_by" to JSONObject(sortedMapOf<String, Any>("entry" to "app.example.com", "added_by" to "asha", "added_on" to "2026-10-12", "note" to "SOW 14")),
            )))),
            "nodes" to org.json.JSONArray(listOf(
                JSONObject(sortedMapOf<String, Any>("id" to "n-1", "name" to "fra-1")),
                JSONObject(sortedMapOf<String, Any>("id" to "n-2", "name" to "blr-2")),
            )),
            "options" to JSONObject(sortedMapOf<String, Any>("severity_min" to "medium")),
            "reason" to "Confirm the SQL injection found earlier",
            "request_digest" to "5d41402abc4b2a76b9719d911017c592".repeat(2),
        )).let(::canonical)
        val digest = ApprovalProtocol.sha256Hex(summary.toByteArray(Charsets.UTF_8))
        val approver = "5b0f6d0e-7a34-4c1b-9b43-0a8f6a5e2f11"
        val signedAt = 1793345642L
        val bytes = ApprovalProtocol.signingBytes(id, "approve", digest, signedAt, approver)
        val sig = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(bytes); sign() }
        val b64 = Base64.getEncoder()
        val out = JSONObject()
            .put("about", "A P-256 approval signature made by the JVM's java.security, as Android's keystore makes them. Shared with the platform's verifier.")
            .put("public_key", b64.encodeToString(pair.public.encoded))
            .put("fingerprint", Spki.fingerprint(pair.public.encoded))
            .put("approval_id", id)
            .put("decision", "approve")
            .put("summary_json", summary)
            .put("digest", digest)
            .put("signed_at", signedAt)
            .put("approver_id", approver)
            .put("signing_bytes_b64", b64.encodeToString(bytes))
            .put("signature", b64.encodeToString(sig))
        File("src/test/resources/approval-sig-v1.json").writeText(out.toString(2) + "\n")
    }

    /** Keys sorted at every level and no whitespace, as the platform writes a summary. */
    private fun canonical(v: Any?): String = when (v) {
        is JSONObject -> v.keys().asSequence().sorted().joinToString(",", "{", "}") { JSONObject.quote(it) + ":" + canonical(v.get(it)) }
        is org.json.JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { canonical(v.get(it)) }
        is String -> JSONObject.quote(v)
        null, JSONObject.NULL -> "null"
        else -> v.toString()
    }
}
