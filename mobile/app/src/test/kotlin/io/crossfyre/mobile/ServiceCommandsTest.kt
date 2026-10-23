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
