package io.crossfyre.mobile.account

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionTest {

    @Test
    fun a_fresh_install_id_is_one_the_pairing_route_accepts() {
        val ids = (1..50).map { DeviceIds.fresh() }
        ids.forEach { assertTrue(it, DeviceIds.isValid(it)) }
        assertEquals("ids repeat", ids.size, ids.toSet().size)
    }

    @Test
    fun the_route_rules_for_an_install_id_hold_here_too() {
        assertTrue(DeviceIds.isValid("abcdefgh"))
        assertTrue(DeviceIds.isValid("A.b_c-1234"))
        assertTrue(DeviceIds.isValid("x".repeat(128)))
        assertFalse(DeviceIds.isValid("short"))
        assertFalse(DeviceIds.isValid("x".repeat(129)))
        assertFalse(DeviceIds.isValid("has space 1"))
        assertFalse(DeviceIds.isValid("slash/12345"))
        assertFalse(DeviceIds.isValid(""))
        // The server refuses "..", since the id ends up in a path.
        assertFalse(DeviceIds.isValid("abc..defgh"))
        assertTrue(DeviceIds.isValid("abc.def.ghi"))
    }

    @Test
    fun a_session_that_just_paired_is_used_as_it_is() {
        val s = SessionState()
        s.paired()
        assertFalse(s.mustRepair(inUse = false, renewable = true))
    }

    @Test
    fun a_stop_ends_the_session_so_the_next_start_pairs_again() {
        val s = SessionState()
        s.paired()
        s.ended()
        assertTrue(s.mustRepair(inUse = false, renewable = true))
    }

    @Test
    fun a_token_in_use_is_never_replaced() {
        // Pairing mints a new token and retires the old one, so pairing under a
        // running capture or patch would cut it off mid-flight.
        val s = SessionState()
        s.ended()
        assertFalse(s.mustRepair(inUse = true, renewable = true))
    }

    @Test
    fun a_qr_pairing_cannot_be_renewed_from_the_phone() {
        val s = SessionState()
        s.ended()
        assertFalse(s.mustRepair(inUse = false, renewable = false))
    }

    @Test
    fun after_a_restart_nothing_is_assumed_live() {
        assertTrue(SessionState().mustRepair(inUse = false, renewable = true))
        assertNotEquals(true, SessionState().live)
    }
}
