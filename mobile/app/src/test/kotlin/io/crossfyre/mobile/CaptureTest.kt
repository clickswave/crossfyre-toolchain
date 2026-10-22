package io.crossfyre.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the capture card claims, and what stands between a tap on Start and a
 * running capture.
 */
class CaptureTest {

    // ── the three states ─────────────────────────────────────────────────────

    @Test
    fun asking_for_capture_reads_as_starting_until_the_service_is_up() {
        val w = StartWatch(graceMs = 8_000)
        assertEquals(Phase.IDLE, w.phase(serviceActive = false, now = 0))
        w.asked(now = 1_000)
        assertEquals(Phase.STARTING, w.phase(serviceActive = false, now = 1_500))
        assertEquals(Phase.CAPTURING, w.phase(serviceActive = true, now = 2_000))
        assertFalse(w.failed)
    }

    @Test
    fun a_start_that_never_arrives_is_said_out_loud() {
        val w = StartWatch(graceMs = 8_000)
        w.asked(now = 1_000)
        assertEquals(Phase.STARTING, w.phase(false, now = 9_000))
        assertEquals(Phase.IDLE, w.phase(false, now = 9_001))
        assertTrue(w.failed)
        // Asking again clears it.
        w.asked(now = 10_000)
        assertFalse(w.failed)
    }

    @Test
    fun a_capture_stopped_elsewhere_stops_being_claimed() {
        val w = StartWatch()
        assertEquals(Phase.CAPTURING, w.phase(true, 0))
        // Stopped from the notification: nothing was asked for, the service went away.
        assertEquals(Phase.IDLE, w.phase(false, 500))
        assertFalse(w.failed)
    }

    // ── the order of the gates ───────────────────────────────────────────────

    @Test
    fun the_disclosure_comes_before_anything_android_asks() {
        assertEquals(StartStep.DISCLOSE, nextStartStep(false, true, false, true, true))
    }

    @Test
    fun a_stale_patch_in_scope_is_raised_before_the_prompts_and_only_once() {
        assertEquals(StartStep.PREFLIGHT, nextStartStep(true, true, false, true, true))
        assertEquals(StartStep.NOTIFICATIONS, nextStartStep(true, true, true, true, true))
    }

    @Test
    fun notifications_are_asked_before_the_vpn() {
        assertEquals(StartStep.NOTIFICATIONS, nextStartStep(true, false, false, true, true))
        assertEquals(StartStep.VPN, nextStartStep(true, false, false, false, true))
        assertEquals(StartStep.START, nextStartStep(true, false, false, false, false))
    }

    // ── scope, in words ──────────────────────────────────────────────────────

    @Test
    fun scope_reads_as_the_card_and_the_row_say_it() {
        val labels = mapOf("a.b" to "Northwind Field", "c.d" to "Firefox")
        val only = Scope(Scope.ONLY, listOf("a.b", "c.d"))
        assertEquals("Only 2 apps", only.title())
        assertEquals("Northwind Field, Firefox", only.sub { labels.getValue(it) })
        assertEquals("only 2 apps", only.inline())

        val except = Scope(Scope.EXCEPT, listOf("a.b"))
        assertEquals("All except 1 app", except.title())
        assertEquals("Left alone: Northwind Field", except.sub { labels.getValue(it) })

        val all = Scope(Scope.ALL, listOf("a.b"))
        assertEquals("Whole phone", all.title())
        assertEquals("the whole phone", all.inline())
    }

    @Test
    fun a_list_scope_with_nothing_ticked_is_the_whole_phone_as_the_service_treats_it() {
        val s = Scope(Scope.ONLY, emptyList())
        assertEquals(Scope.ALL, s.effectiveMode)
        assertEquals("Whole phone", s.title())
    }

    private fun stats(events: Long = 0, sent: Long = 0, rejected: Long = 0, failed: Long = 0) =
        Stats(10, 9, 0, 0, events, sent, rejected, failed, 0, "", "")

    @Test
    fun the_card_line_says_where_requests_went_or_that_they_did_not() {
        val scope = Scope(Scope.ONLY, listOf("a", "b"))
        assertEquals("Not capturing. Scope: only 2 apps.", capLine(Phase.IDLE, scope, null, "w"))
        assertEquals("Android is bringing the tunnel up.", capLine(Phase.STARTING, scope, null, "w"))
        assertEquals(
            "1,184 requests sent to client-app-audit. Scope: only 2 apps.",
            capLine(Phase.CAPTURING, scope, stats(events = 1_201, sent = 1_184), "client-app-audit"),
        )
        assertEquals(
            "12 requests captured, 0 sent. Scope: only 2 apps.",
            capLine(Phase.CAPTURING, scope, stats(events = 12, rejected = 3), "client-app-audit"),
        )
        assertEquals(
            "1 request sent to w. Scope: only 2 apps.",
            capLine(Phase.CAPTURING, scope, stats(events = 1, sent = 1), "w"),
        )
    }

    // ── the kept requests ────────────────────────────────────────────────────

    @Test
    fun kept_requests_are_read_from_the_native_list() {
        val json = """[
            {"method":"POST","url":"https://api.example.test/v2/auth/token?grant=","status":200,
             "authed":false,"body_params":["username","password"],"at_ms":1000,"sent":true},
            {"method":"GET","url":"https://api.example.test","status":null,"authed":true,"at_ms":900,"sent":false}
        ]"""
        val list = RecentRequest.parseList(json)
        assertEquals(2, list.size)
        val r = list[0]
        assertEquals("api.example.test", r.host)
        assertEquals("/v2/auth/token?grant=", r.path)
        assertEquals("/v2/auth/token", r.pathOnly)
        assertEquals(listOf("username", "password"), r.bodyFields)
        assertTrue(r.sent)
        assertNull(list[1].status)
        assertEquals("/", list[1].path)
        assertTrue(RecentRequest.parseList("not json").isEmpty())
    }

    @Test
    fun ages_read_like_a_person_would_say_them() {
        assertEquals("just now", ago(1))
        assertEquals("12s ago", ago(12))
        assertEquals("3m ago", ago(200))
        assertEquals("2h ago", ago(7300))
    }

    // ── small formatting ─────────────────────────────────────────────────────

    @Test
    fun a_device_code_shows_its_two_ends() {
        val code = "cfd_7c41e2b93d0f5a6e81c24b7d9f02a6c3e5b81d47a2c9e06f13b5d8a7c4e2f905a90be09"
        assertEquals("cfd_7c41e2b9" to "5a90be09", codeEnds(code))
        assertNull(codeEnds("SHORT-CODE"))
    }

    @Test
    fun a_fingerprint_is_four_lines_of_four_groups() {
        val hex = "4f1a9c0722be81d05c3ea1f90b476d2a" + "0".repeat(32)
        val lines = fingerprintLines(hex)
        assertEquals(4, lines.size)
        assertEquals("4F1A 9C07 22BE 81D0", lines[0])
    }

    @Test
    fun a_host_is_shown_without_its_scheme_and_with_its_port() {
        assertEquals("crossfyre.io", displayHost("https://crossfyre.io"))
        assertEquals("10.0.2.2:12004", displayHost("http://10.0.2.2:12004"))
    }
}

class DisclosureScopeTest {
    private val labels = mapOf("com.android.chrome" to "Chrome", "org.mozilla.firefox" to "Firefox", "a.b" to "Bank")

    @Test
    fun the_disclosure_states_the_scope_that_is_set_now() {
        assertEquals(
            "Only Chrome is in scope. Every other app works as normal, untouched.",
            Scope(Scope.ONLY, listOf("com.android.chrome")).disclosure { labels.getValue(it) },
        )
        assertEquals(
            "Only Chrome and Firefox are in scope. Every other app works as normal, untouched.",
            Scope(Scope.ONLY, listOf("com.android.chrome", "org.mozilla.firefox")).disclosure { labels.getValue(it) },
        )
        assertEquals(
            "Every app is in scope except Bank, which is left alone.",
            Scope(Scope.EXCEPT, listOf("a.b")).disclosure { labels.getValue(it) },
        )
        val whole = Scope(Scope.ALL, emptyList()).disclosure { it }
        assertTrue(whole, whole.startsWith("Scope is the whole phone"))
        // Only these, with nothing ticked, is the whole phone as the service runs it.
        assertEquals(whole, Scope(Scope.ONLY, emptyList()).disclosure { it })
    }
}
