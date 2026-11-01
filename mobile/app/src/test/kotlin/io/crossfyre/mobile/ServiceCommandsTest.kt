package io.crossfyre.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * How the capture service reads what it is sent, and how it stops.
 *
 * Capture starts only when the app asks for it with the person's scope. Android
 * also delivers intents of its own: a restart of a sticky service carries no
 * intent at all, and an always-on VPN arrives as the VpnService action. Neither
 * carries a scope, and starting on them would capture the whole phone.
 */
class ServiceCommandsTest {

    @Test
    fun only_the_apps_own_start_starts_a_capture() {
        assertEquals(Command.START, commandFor(TracerVpnService.ACTION_START))
        assertEquals(Command.STOP, commandFor(TracerVpnService.ACTION_STOP))
        assertEquals("a restart by Android carries no intent", Command.STOP, commandFor(null))
        assertEquals(Command.STOP, commandFor("android.net.VpnService"))
        assertEquals(Command.STOP, commandFor("something.else"))
    }

    @Test
    fun every_step_of_a_stop_runs_in_order_even_when_one_fails() {
        val ran = mutableListOf<String>()
        val failed = Teardown(
            listOf(
                "native" to { ran += "native"; throw IllegalStateException("native teardown failed") },
                "tunnel" to { ran += "tunnel" },
                "notification" to { ran += "notification" },
                "service" to { ran += "service" },
            )
        ).run()
        assertEquals(listOf("native", "tunnel", "notification", "service"), ran)
        assertEquals(listOf("native"), failed)
    }

    /** A [TokenWatch] whose looks run when the test says, and the stops it asked for. */
    private class Watched(var stats: String?) {
        val due = ArrayDeque<() -> Unit>()
        var stops = 0
        val watch = TokenWatch({ stats }, { stops++ }) { ms, look ->
            assertEquals(TokenWatch.EVERY_MS, ms)
            due.addLast(look)
        }

        fun tick() = due.removeFirst()()
    }

    @Test
    fun a_capture_whose_token_the_server_refused_stops_itself_once() {
        val w = Watched("""{"events": 3, "token_refused": false}""")
        w.watch.start()
        w.tick()
        assertEquals(0, w.stops)
        assertEquals("it keeps looking while the token is taken", 1, w.due.size)
        // Nothing from the native side yet, or nothing readable: look again later.
        w.stats = null
        w.tick()
        w.stats = "not json"
        w.tick()
        assertEquals(0, w.stops)
        w.stats = """{"events": 4, "token_refused": true}"""
        w.tick()
        assertEquals(1, w.stops)
        assertTrue("it stops looking once it has stopped the capture", w.due.isEmpty())
    }

    @Test
    fun a_capture_stopped_for_another_reason_is_not_stopped_again() {
        val w = Watched("""{"token_refused": true}""")
        w.watch.start()
        w.watch.cancel()
        w.tick()
        assertEquals(0, w.stops)
        assertTrue(w.due.isEmpty())
    }

    @Test
    fun a_second_stop_does_nothing() {
        var count = 0
        val t = Teardown(listOf("tunnel" to { count++ }))
        t.run()
        t.run()
        assertEquals(1, count)
        assertTrue(t.run().isEmpty())
    }
}
