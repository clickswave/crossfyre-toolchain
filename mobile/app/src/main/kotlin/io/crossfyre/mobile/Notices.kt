package io.crossfyre.mobile

import io.crossfyre.mobile.account.Problem
import io.crossfyre.mobile.account.Refusal

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
    listTrouble(p) == ListTrouble.UNVERIFIED || listTrouble(p) == ListTrouble.SUSPENDED || p == Problem.SignedOut -> listNotice(p, host)
    p is Problem.Unreachable -> Notice(Level.DANGER, "Couldn't pair this phone.", "$host didn't answer. Check the phone's connection and try again.")
    else -> Notice(Level.DANGER, "Couldn't pair this phone.", p.text)
}
