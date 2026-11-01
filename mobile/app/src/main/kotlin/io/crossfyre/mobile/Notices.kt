package io.crossfyre.mobile

import io.crossfyre.mobile.account.Problem
import io.crossfyre.mobile.account.Refusal
import io.crossfyre.mobile.approve.SignOutLeft

/** How loud a message is: the banner colour, and whether it is read out as an alert. */
enum class Level { OK, WARN, DANGER, INFO }

/** A banner's worth of words. */
data class Notice(val level: Level, val title: String, val body: String)

/**
 * What the sign-in screen says about a refusal.
 *
 * Each refusal the server can give gets its own sentence, because the point of
 * telling them apart is the next step: an account made with Google is sent to
 * the browser button, an enterprise account in review is told it is waiting on
 * us, and only a real mismatch is called a wrong password.
 *
 * @param host the server the app tried, named because on a dev or staging build
 *   that is the first thing to check.
 */
/** Which refusal a problem is, when it is one the screens tell apart. */
fun reasonOf(p: Problem): Refusal = (p as? Problem.Refused)?.reason ?: Refusal.OTHER

fun signInNotice(p: Problem, host: String): Notice = when {
    p is Problem.Unreachable -> Notice(Level.DANGER, "Can't reach $host.", "Check the phone's connection and try again.")
    reasonOf(p) == Refusal.IN_REVIEW -> Notice(
        Level.WARN, "Your enterprise request is in review.",
        "We'll be in touch at your registered email once it's approved.",
    )
    reasonOf(p) == Refusal.RATE_LIMITED -> Notice(Level.WARN, "Too many sign-in attempts.", "Wait a few minutes, then try again.")
    else -> signInOther(p)
}

private fun signInOther(p: Problem): Notice = when (p) {
    Problem.WrongPassword -> Notice(Level.DANGER, "Could not sign in.", "The username or email and password don't match.")
    Problem.UseGoogle -> Notice(
        Level.INFO, "This account signs in with Google.",
        "It has no password. Use Sign in with browser below, and pick Google on the page that opens.",
    )
    else -> Notice(Level.DANGER, "Could not sign in.", p.text)
}

/** What the browser sign-in says when it could not even start. */
fun deviceStartNotice(p: Problem, host: String): Notice = when (p) {
    is Problem.Unreachable -> Notice(Level.DANGER, "Couldn't start the sign-in.", "$host didn't answer. Check the phone's connection and try again.")
    else -> Notice(Level.DANGER, "Couldn't start the sign-in.", p.text)
}

/** Why the workspace list did not load, and so what the screen offers instead of it. */
enum class ListTrouble { UNREACHABLE, UNVERIFIED, SUSPENDED, SIGNED_OUT, OTHER }

fun listTrouble(p: Problem): ListTrouble = when {
    p is Problem.Unreachable -> ListTrouble.UNREACHABLE
    p == Problem.SignedOut -> ListTrouble.SIGNED_OUT
    reasonOf(p) == Refusal.EMAIL_UNVERIFIED -> ListTrouble.UNVERIFIED
    reasonOf(p) == Refusal.ACCOUNT_SUSPENDED -> ListTrouble.SUSPENDED
    else -> ListTrouble.OTHER
}

fun listNotice(p: Problem, host: String): Notice = when (listTrouble(p)) {
    ListTrouble.UNREACHABLE -> Notice(Level.DANGER, "Couldn't load your workspaces.", "$host didn't answer. Check the phone's connection.")
    // Sign-in itself works for these two. The refusal comes from the list, which
    // checks the account the way the dashboard does on every page.
    ListTrouble.UNVERIFIED -> Notice(
        Level.WARN, "Verify your email address first.",
        "Open the link in the email we sent when you signed up, or ask for a new one in the dashboard. Then try again.",
    )
    ListTrouble.SUSPENDED -> Notice(
        Level.DANGER, "This account is suspended.",
        "Until it is lifted, this phone cannot pair with a workspace. The dashboard shows the reason and how to appeal.",
    )
    ListTrouble.SIGNED_OUT -> Notice(Level.WARN, "You have been signed out.", "This phone's key no longer works. Sign in again.")
    ListTrouble.OTHER -> Notice(Level.DANGER, "Couldn't load your workspaces.", p.text)
}

/** What pairing with the chosen workspace says when the server refuses it. */
fun pairNotice(p: Problem, host: String): Notice = when {
    reasonOf(p) == Refusal.WORKSPACE_ARCHIVED -> Notice(Level.DANGER, "This workspace is archived.", "Restore it in the dashboard, or pick another workspace.")
    reasonOf(p) == Refusal.WORKSPACE_SUSPENDED -> Notice(
        Level.DANGER, "This workspace is suspended.",
        "The organization that owns it is suspended. Pick another workspace, or ask its admin.",
    )
    reasonOf(p) == Refusal.NOT_MEMBER -> Notice(Level.DANGER, "You're not a member of this workspace any more.", "Someone removed you, or it was deleted. Pick another one.")
    // Pairing starts a capture into the workspace, which a role has to allow.
    reasonOf(p) == Refusal.MISSING_PERMISSION -> Notice(
        Level.WARN, "Your role doesn't allow capture in this workspace.",
        "${p.text} Ask a workspace admin for a role that can start scans, or pick another workspace.",
    )
    listTrouble(p) == ListTrouble.UNVERIFIED || listTrouble(p) == ListTrouble.SUSPENDED || p == Problem.SignedOut -> listNotice(p, host)
    p is Problem.Unreachable -> Notice(Level.DANGER, "Couldn't pair this phone.", "$host didn't answer. Check the phone's connection and try again.")
    else -> Notice(Level.DANGER, "Couldn't pair this phone.", p.text)
}

/** What turning on approvals says when the server will not take this phone. */
fun enrolNotice(p: Problem, host: String): Notice = when {
    p is Problem.Unreachable -> Notice(Level.DANGER, "Couldn't turn on approvals.", "$host didn't answer. Check the phone's connection and try again.")
    reasonOf(p) == Refusal.TOO_MANY_APPROVERS -> Notice(
        Level.WARN, "This account has as many approval phones as it may.",
        "Turn Approvals off on a phone you no longer use, or sign that phone out, then try again.",
    )
    listTrouble(p) == ListTrouble.UNVERIFIED || listTrouble(p) == ListTrouble.SUSPENDED -> listNotice(p, host)
    else -> Notice(Level.DANGER, "Couldn't turn on approvals.", p.text)
}

/** What the approval screen says when a decision did not go through. */
fun decisionNotice(p: Problem, host: String): Notice = when {
    p is Problem.Unreachable -> Notice(Level.DANGER, "Couldn't send your answer.", "$host didn't answer, so nothing was decided. Try again.")
    reasonOf(p) == Refusal.NOT_PENDING -> Notice(Level.INFO, "This request is no longer waiting.", "It was decided somewhere else, or cancelled.")
    reasonOf(p) == Refusal.APPROVAL_EXPIRED -> Notice(Level.WARN, "This request expired.", "Nothing was started. The agent has to ask again.")
    reasonOf(p) == Refusal.UNKNOWN -> Notice(Level.INFO, "This request is gone.", "The server no longer has it, so there is nothing to decide.")
    reasonOf(p) == Refusal.BAD_SIGNATURE -> Notice(
        Level.DANGER, "The server did not accept this phone's signature.",
        "Nothing was approved. Turn Approvals off and on again in Settings, then ask the agent to try again.",
    )
    reasonOf(p) == Refusal.APPROVER_INACTIVE -> Notice(Level.WARN, "This phone no longer approves.", "Turn Approvals on again in Settings.")
    // Only an approve asks the role: the launch would start a scan as this member.
    reasonOf(p) == Refusal.MISSING_PERMISSION -> Notice(Level.WARN, "Not approved.", "${p.text} Ask a workspace admin for a role that can start scans.")
    reasonOf(p) == Refusal.RATE_LIMITED -> Notice(Level.WARN, "Too many requests from this phone.", "Nothing was decided. Wait a minute, then try again.")
    else -> Notice(Level.DANGER, "Couldn't send your answer.", p.text)
}

/** What Recent decisions says when a stop did not go through. */
fun stopNotice(p: Problem, host: String): Notice = when {
    p is Problem.Unreachable -> Notice(Level.DANGER, "Couldn't send the stop.", "$host didn't answer, so nothing was stopped. Try again.")
    reasonOf(p) == Refusal.NOT_RUNNING -> Notice(Level.INFO, "That scan is not running any more.", "It finished or was stopped before this reached it.")
    reasonOf(p) == Refusal.NOT_LAUNCHED -> Notice(Level.INFO, "That request did not start a scan.", "There is nothing to stop.")
    reasonOf(p) == Refusal.UNKNOWN -> Notice(Level.INFO, "The server no longer has that request.", "There is nothing to stop.")
    reasonOf(p) == Refusal.MISSING_PERMISSION -> Notice(Level.WARN, "Not stopped.", "${p.text} Ask a workspace admin to stop it.")
    reasonOf(p) == Refusal.NOT_MEMBER -> Notice(Level.WARN, "You're not a member of that workspace any more.", "Nothing was stopped. Ask someone in it to stop the scan.")
    reasonOf(p) == Refusal.BAD_SIGNATURE -> Notice(
        Level.DANGER, "The server did not accept this phone's signature.",
        "Nothing was stopped. Turn Approvals off and on again in Settings.",
    )
    reasonOf(p) == Refusal.STALE_SIGNATURE -> Notice(
        Level.WARN, "This phone's time and the server's were too far apart.",
        "Nothing was stopped. Refresh this tab, then tap Stop again.",
    )
    reasonOf(p) == Refusal.APPROVER_INACTIVE -> Notice(
        Level.WARN, "This phone no longer approves.",
        "Only a phone that approves can stop a scan. Turn Approvals on again in Settings.",
    )
    reasonOf(p) == Refusal.RATE_LIMITED -> Notice(Level.WARN, "Too many requests from this phone.", "Nothing was stopped. Wait a minute, then try again.")
    reasonOf(p) == Refusal.APPROVALS_OFF -> Notice(Level.WARN, "Approvals are switched off on $host.", "Nothing was stopped. Stop the scan in the dashboard.")
    else -> Notice(Level.DANGER, "Couldn't stop the scan.", p.text)
}

/**
 * What the sign-in screen says after a sign-out the server did not confirm, or
 * null when it did. The phone has forgotten the key either way, so the only
 * way left to revoke it is the dashboard.
 */
fun signOutNotice(left: SignOutLeft, host: String): Notice? = when (left) {
    SignOutLeft.NOTHING -> null
    SignOutLeft.KEY -> Notice(
        Level.WARN, "Signed out on this phone only.",
        "$host did not confirm that this phone's key is revoked, so it may still work. Revoke it in the dashboard, under Settings > CLI Access.",
    )
    SignOutLeft.APPROVER -> Notice(
        Level.WARN, "Signed out on this phone only.",
        "$host did not confirm the sign-out, so it may still count this phone as an approver and hold agent requests for it. Revoke this phone's key in the dashboard, under Settings > CLI Access.",
    )
}

/** Why the activity log did not load. */
fun activityNotice(p: Problem, host: String): Notice = readNotice("activity", p, host)

/** Why the notifications did not load, or were not marked read. */
fun inboxNotice(p: Problem, host: String): Notice = readNotice("notifications", p, host)

/** Why notifications could not be marked read. They stay unread on the server, and so here. */
fun markReadNotice(p: Problem, host: String): Notice = when {
    p is Problem.Unreachable -> Notice(Level.WARN, "Couldn't mark notifications read.", "$host didn't answer. They stay unread for now.")
    else -> readNotice("notifications", p, host).copy(title = "Couldn't mark notifications read.")
}

private fun readNotice(what: String, p: Problem, host: String): Notice = when {
    p is Problem.Unreachable -> Notice(Level.DANGER, "Couldn't load $what.", "$host didn't answer. Check the phone's connection.")
    reasonOf(p) == Refusal.RATE_LIMITED -> Notice(Level.WARN, "Too many requests from this phone.", "The app waits a minute before it asks $host again.")
    reasonOf(p) == Refusal.APPROVALS_OFF -> Notice(Level.INFO, "Approvals are switched off on $host.", "The dashboard still shows your $what.")
    // Only a phone that approves is answered. The app asks the pending list
    // whether this one still does, and says so there if not.
    reasonOf(p) == Refusal.APPROVER_INACTIVE -> Notice(
        Level.WARN, "$host does not count this phone as an approver.",
        "Only a phone that approves can read your $what here. If this stays, turn Approvals off and on again in Settings.",
    )
    else -> Notice(Level.DANGER, "Couldn't load $what.", p.text)
}
