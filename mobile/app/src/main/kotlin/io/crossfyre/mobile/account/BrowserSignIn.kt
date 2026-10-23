package io.crossfyre.mobile.account

/**
 * Wait for a browser sign-in to be approved, declined, or to lapse.
 *
 * Polls at the interval the server asked for, and never faster than once a
 * second whatever it asked. The approval carries the account key and is handed
 * over once (the next poll says expired), so it is returned the moment it is
 * seen. A poll that gets no answer at all is tried again rather than ending the
 * wait: the request lives on the server, and a phone moving between Wi-Fi and
 * mobile data while someone approves on the same phone is the normal case here,
 * not an error. Any other refusal ends it.
 *
 * [sleep] and [now] are the clock, so the wait can be tested without one.
 */
suspend fun awaitApproval(
    login: DeviceLogin,
    poll: (String) -> Outcome<Poll>,
    sleep: suspend (Long) -> Unit,
    now: () -> Long,
): Outcome<SignedIn> {
    val interval = login.intervalSeconds.coerceIn(1, 30) * 1000L
    val deadline = now() + login.expiresInSeconds.coerceAtLeast(1) * 1000L
    while (now() < deadline) {
        sleep(interval)
        when (val answer = poll(login.deviceCode)) {
            is Outcome.Ok -> when (val state = answer.value) {
                Poll.Waiting -> Unit
                is Poll.Approved -> return Outcome.Ok(state.signedIn)
                Poll.Denied -> return Outcome.Failed(Problem.Declined)
                Poll.Expired -> return Outcome.Failed(Problem.Expired)
            }
            is Outcome.Failed -> if (answer.problem !is Problem.Unreachable) return answer
        }
    }
    return Outcome.Failed(Problem.Expired)
}
