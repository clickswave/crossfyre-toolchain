package io.crossfyre.mobile.approve

import io.crossfyre.mobile.account.AccountStore
import io.crossfyre.mobile.account.Outcome
import io.crossfyre.mobile.account.Problem

/**
 * Which approver this phone is enrolling, which it is, and which it has let go
 * of but the server may still count.
 *
 * Once an account has an active approver, only a signature from that phone
 * approves what an agent asks for. A row the server still holds after the phone
 * deleted its key would leave every such request waiting for a phone that cannot
 * sign, while the app shows Approvals off and never looks. So every approver the
 * phone gives up on is written down first, and crossed off only when the server
 * has said it is revoked. All of it is kept in [AccountStore], so it outlives the
 * process, and what is still owed is sent again at the next start, resume and
 * enrolment.
 */
class ApproverLedger(private val store: AccountStore) {

    /** `approver/start` answered with [id]. Written before the browser opens, so a wait the process does not survive is not lost. */
    @Synchronized
    fun started(id: String) {
        store.enrollingApproverId = id
    }

    /**
     * The browser confirmed [id], and this phone now approves as it. False when
     * the enrolment was let go of first, by a cancel that crossed the answer:
     * that approver is already owed a revoke and stays so.
     */
    @Synchronized
    fun confirmed(id: String, fingerprint: String): Boolean {
        if (store.enrollingApproverId != id) return false
        store.approverId = id
        store.approverFingerprint = fingerprint
        store.enrollingApproverId = null
        return true
    }

    /** The wait for [id] ended without a confirmation: let it go, unless a cancel or a sign-out already dealt with it. */
    @Synchronized
    fun stopped(id: String) {
        if (store.enrollingApproverId == id) letGo(id)
    }

    /** This phone no longer approves as [id], or never will: the server is owed a revoke for it. */
    @Synchronized
    fun letGo(id: String) {
        store.revokesOwed = store.revokesOwed + id
        if (store.enrollingApproverId == id) store.enrollingApproverId = null
        if (store.approverId == id) {
            store.approverId = null
            store.approverFingerprint = null
        }
    }

    /** Sign-out: the approver this phone is and the one it is enrolling are both given up. */
    @Synchronized
    fun letGoAll() {
        store.approverId?.let(::letGo)
        store.enrollingApproverId?.let(::letGo)
    }

    /**
     * At start, before any wait can be running: an enrolment the last process
     * began and never finished is let go of. True when there was one, so the
     * caller deletes the key it made.
     */
    @Synchronized
    fun abandoned(): Boolean {
        val id = store.enrollingApproverId ?: return false
        if (id == store.approverId) {
            store.enrollingApproverId = null
            return false
        }
        letGo(id)
        return true
    }

    val owed: Set<String>
        @Synchronized get() = store.revokesOwed

    @Synchronized
    private fun crossOff(id: String) {
        store.revokesOwed = store.revokesOwed - id
    }

    @Synchronized
    private fun forgive() {
        store.revokesOwed = emptySet()
    }

    /**
     * Send every revoke still owed. An approver the server confirms revoked, or
     * no longer knows, is crossed off; one it could not be told about stays for
     * next time, and the last such failure is returned. A key the server no
     * longer takes crosses off everything, since revoking or deleting the key
     * ended every approver it had.
     */
    fun settle(revoke: (String) -> Outcome<Unit>): Outcome<Unit> {
        var last: Outcome<Unit> = Outcome.Ok(Unit)
        for (id in owed) {
            when (val r = revoke(id)) {
                is Outcome.Ok -> crossOff(id)
                is Outcome.Failed -> {
                    if (r.problem == Problem.SignedOut) {
                        forgive()
                        return r
                    }
                    last = r
                }
            }
        }
        return last
    }

    /**
     * Sign-out's part, run while the account key is still on the phone: every
     * approver it holds, is enrolling or still owes a revoke for is revoked
     * first, while the key that sends those revokes still works, and then the
     * key itself. The caller forgets all of it locally afterwards, whatever the
     * answer, and tells the person what the server may still count.
     */
    fun signOut(revoke: (String) -> Outcome<Unit>, logout: () -> Outcome<Unit>): SignOutLeft {
        letGoAll()
        settle(revoke)
        return when {
            // Every approver check joins the key, so a revoked key ends them all.
            logout() is Outcome.Ok -> SignOutLeft.NOTHING
            owed.isEmpty() -> SignOutLeft.KEY
            else -> SignOutLeft.APPROVER
        }
    }
}

/** What the server may still count after a sign-out, by what it confirmed. */
enum class SignOutLeft {
    /** The key is revoked, and every approver it had with it. */
    NOTHING,
    /** Every approver is revoked, but not the key, which still works on the server until it is revoked in the dashboard. */
    KEY,
    /** Neither: the server may still wait for this phone to approve what an agent asks for. */
    APPROVER,
}
