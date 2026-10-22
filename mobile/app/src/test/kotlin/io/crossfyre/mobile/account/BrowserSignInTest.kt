package io.crossfyre.mobile.account

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Waiting on a browser sign-in, with the clock and the network replaced.
 *
 * The approval is handed over once: the poll after it says expired. So the loop
 * has to return the key the moment it sees it, and a lost poll on a phone that
 * is changing networks must not abandon a sign-in the person is still approving.
 */
class BrowserSignInTest {

    private val user = AccountUser("u-1", "kew", "kew@example.com", "personal", true)
    private val approved = SignedIn("cfk_" + "e".repeat(32), user)

    /** A clock that only moves when the loop sleeps. */
    private class Clock {
        var ms = 0L
        val slept = mutableListOf<Long>()
        suspend fun sleep(d: Long) {
            slept += d
            ms += d
        }
    }

    private fun login(interval: Int = 3, expires: Int = 600) =
        DeviceLogin("cfd_code", "https://crossfyre.io/device?code=cfd_code", interval, expires)

    private fun answers(vararg replies: Outcome<Poll>): (String) -> Outcome<Poll> {
        val queue = ArrayDeque(replies.toList())
        return { code ->
            assertEquals("cfd_code", code)
            queue.removeFirst()
        }
    }

    @Test
    fun approval_is_returned_after_waiting_at_the_servers_interval() = runBlocking {
        val clock = Clock()
        val got = awaitApproval(
            login(interval = 3),
            answers(Outcome.Ok(Poll.Waiting), Outcome.Ok(Poll.Waiting), Outcome.Ok(Poll.Approved(approved))),
            clock::sleep, { clock.ms },
        )
        assertEquals(Outcome.Ok(approved), got)
        assertEquals(listOf(3000L, 3000L, 3000L), clock.slept)
    }

    @Test
    fun a_declined_sign_in_stops_and_says_so() = runBlocking {
        val clock = Clock()
        val got = awaitApproval(login(), answers(Outcome.Ok(Poll.Waiting), Outcome.Ok(Poll.Denied)), clock::sleep, { clock.ms })
        assertEquals(Outcome.Failed(Problem.Declined), got)
    }

    @Test
    fun an_expired_request_stops_and_says_so() = runBlocking {
        val clock = Clock()
        val got = awaitApproval(login(), answers(Outcome.Ok(Poll.Expired)), clock::sleep, { clock.ms })
        assertEquals(Outcome.Failed(Problem.Expired), got)
    }

    @Test
    fun nobody_approving_before_the_request_lapses_ends_the_wait() = runBlocking {
        val clock = Clock()
        var polls = 0
        val got = awaitApproval(login(interval = 3, expires = 9), { polls++; Outcome.Ok(Poll.Waiting) }, clock::sleep, { clock.ms })
        assertEquals(Outcome.Failed(Problem.Expired), got)
        assertEquals(3, polls)
    }

    @Test
    fun a_poll_lost_to_a_bad_network_is_tried_again() = runBlocking {
        val clock = Clock()
        val got = awaitApproval(
            login(),
            answers(Outcome.Failed(Problem.Unreachable("crossfyre.io")), Outcome.Ok(Poll.Approved(approved))),
            clock::sleep, { clock.ms },
        )
        assertEquals(Outcome.Ok(approved), got)
    }

    @Test
    fun an_unknown_request_stops_with_the_servers_reason() = runBlocking {
        val clock = Clock()
        val gone = Outcome.Failed(Problem.Refused(404, "Unknown login request"))
        assertEquals(gone, awaitApproval(login(), answers(gone), clock::sleep, { clock.ms }))
    }

    @Test
    fun a_server_interval_of_zero_does_not_spin() = runBlocking {
        val clock = Clock()
        awaitApproval(login(interval = 0), answers(Outcome.Ok(Poll.Approved(approved))), clock::sleep, { clock.ms })
        assertEquals(listOf(1000L), clock.slept)
    }
}
