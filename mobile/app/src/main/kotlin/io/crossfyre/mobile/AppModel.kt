package io.crossfyre.mobile

import android.app.Application
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.crossfyre.mobile.account.AccountApi
import io.crossfyre.mobile.account.AccountStore
import io.crossfyre.mobile.account.ChosenWorkspace
import io.crossfyre.mobile.account.ClientInfo
import io.crossfyre.mobile.account.DeviceLogin
import io.crossfyre.mobile.account.HttpTransport
import io.crossfyre.mobile.account.KeystoreSealer
import io.crossfyre.mobile.account.Outcome
import io.crossfyre.mobile.account.PrefsKeyValues
import io.crossfyre.mobile.account.Problem
import io.crossfyre.mobile.account.SessionState
import io.crossfyre.mobile.account.SignedIn
import io.crossfyre.mobile.account.StoredUser
import io.crossfyre.mobile.account.Workspace
import io.crossfyre.mobile.account.awaitApproval
import io.crossfyre.mobile.apps.AppFacts
import io.crossfyre.mobile.apps.Apps
import io.crossfyre.mobile.apps.InstalledApp
import io.crossfyre.mobile.patch.Distribution
import io.crossfyre.mobile.patch.PatchFeature
import io.crossfyre.mobile.patch.PatchState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

enum class Route { SIGN_IN, DEVICE, WORKSPACES, MAIN }

/** A screen pushed over a section, with a back arrow. */
sealed interface Push {
    data object Certificate : Push
    data class App(val pkg: String) : Push
    data object Licences : Push
}

/** Sheets and dialogs drawn over the current screen. */
sealed interface Overlay {
    data object Disclosure : Overlay
    data object HowTo : Overlay
    data object Scope : Overlay
    data object FullConsent : Overlay
    /** One kept request, by its own identity rather than its place in a list that grows at the top. */
    data class Request(val key: String) : Overlay
    data object Server : Overlay
    data class Preflight(val apps: List<String>) : Overlay
    data class PairConfirm(val pairing: Pairing) : Overlay
    data object PairInvalid : Overlay
    data object ResetCert : Overlay
    data object RemoveOldCert : Overlay
    data object SignOut : Overlay
    data object Unpair : Overlay
    data class Licence(val name: String, val licence: String) : Overlay
}

/** Things only the activity can do: Android's own prompts, pickers and other apps. */
sealed interface Effect {
    data object AskNotifications : Effect
    data class AskVpn(val intent: Intent) : Effect
    data object Scan : Effect
    data class SaveCa(val fileName: String) : Effect
    data class ExportApk(val fileName: String) : Effect
    data class OpenUrl(val url: String) : Effect
    data object NotificationSettings : Effect
    data object SecuritySettings : Effect
}

enum class DeviceStatus { OPENING, WAITING, DENIED, EXPIRED, ERROR }
enum class ListStatus { LOADING, READY, ERROR, EMPTY }

data class Toast(val text: String, val icon: Int)

/** Facts about this phone's certificate, read off disk and the Android trust store. */
data class CertInfo(val exists: Boolean, val fingerprint: String?, val madeAt: Long, val inAndroid: Boolean)

/**
 * Everything the screens show and every action they take.
 *
 * Kept apart from the activity so that rotating the phone, or Android recreating
 * the activity behind a system prompt, does not drop a sign-in or a pairing that
 * is half done. Android's own prompts go out through [effects], because only an
 * activity can show them.
 */
class AppModel(app: Application) : AndroidViewModel(app) {
    private val ctx: Application = app
    val prefs = AppPrefs(app)
    val store = AccountStore(PrefsKeyValues(app), KeystoreSealer())
    val patch: PatchFeature = Distribution.patchFeature(app)

    private val effectChannel = Channel<Effect>(Channel.BUFFERED)
    val effects = effectChannel.receiveAsFlow()
    private fun emit(e: Effect) {
        effectChannel.trySend(e)
    }

    // ── Environment ──────────────────────────────────────────────────────────

    /** "prod", "staging" or "dev": which control plane this build is for. */
    val env: String = BuildConfig.FLAVOR_env
    val originEditable: Boolean = BuildConfig.ORIGIN_EDITABLE

    /** The server the account lives on. Only the dev build can point somewhere else. */
    var origin by mutableStateOf(
        (if (BuildConfig.ORIGIN_EDITABLE) store.origin() else null) ?: BuildConfig.DEFAULT_ORIGIN
    )
        private set

    val host: String get() = displayHost(origin)
    private fun api() = AccountApi(origin, HttpTransport())

    // ── Navigation ───────────────────────────────────────────────────────────

    private val routeState = mutableStateOf(Route.SIGN_IN)

    /** Where the app is. Moving anywhere closes whatever sheet or dialog was open over the last place. */
    var route: Route
        get() = routeState.value
        set(value) {
            if (value != routeState.value) overlay = null
            routeState.value = value
        }
    var tab by mutableStateOf("home")
    var push by mutableStateOf<Push?>(null)
    var overlay by mutableStateOf<Overlay?>(null)
    var toast by mutableStateOf<Toast?>(null)
        private set
    private var toastJob: Job? = null

    fun say(text: String, icon: Int = R.drawable.ic_check_circle) {
        toast = Toast(text, icon)
        toastJob?.cancel()
        toastJob = viewModelScope.launch {
            delay(3200)
            toast = null
        }
    }

    fun goTab(t: String) {
        tab = t
        push = null
        overlay = null
    }

    /** The system back gesture: close what is on top, one layer at a time. Returns false when there is nothing to close. */
    fun back(): Boolean {
        val o = overlay
        if (o != null) {
            // A running patch cannot be swiped away; its sheet has its own Cancel.
            if (patch.job.value?.running == true) return true
            overlay = null
            return true
        }
        if (patch.job.value != null && patch.job.value?.running == false) {
            patch.dismiss()
            return true
        }
        if (push != null) {
            push = null
            return true
        }
        return when (route) {
            Route.DEVICE -> { cancelDevice(); true }
            Route.WORKSPACES -> if (wsBack) { route = Route.MAIN; true } else false
            Route.MAIN -> if (tab != "home") { tab = "home"; true } else false
            Route.SIGN_IN -> false
        }
    }

    // ── Account ──────────────────────────────────────────────────────────────

    var user by mutableStateOf<StoredUser?>(store.user())
        private set
    val signedIn: Boolean get() = user != null
    var signedInWith by mutableStateOf(store.signedInWith)
        private set

    /** The account key was refused: revoked in the dashboard, or signed out elsewhere. */
    var revoked by mutableStateOf(false)
        private set

    // Sign-in form.
    var siUser by mutableStateOf("")
    var siPass by mutableStateOf("")
    var siShow by mutableStateOf(false)
    var siBusy by mutableStateOf(false)
        private set
    var siError by mutableStateOf<Notice?>(null)
        private set
    var siEmpty by mutableStateOf(false)
        private set

    fun signIn() {
        if (siBusy) return
        if (siUser.isBlank() || siPass.isEmpty()) {
            siEmpty = true
            return
        }
        siEmpty = false
        siError = null
        siBusy = true
        viewModelScope.launch {
            val r = withContext(Dispatchers.IO) { api().login(siUser.trim(), siPass, keyName()) }
            siBusy = false
            when (r) {
                is Outcome.Ok -> {
                    siPass = ""
                    signedInAs(r.value, "password")
                }
                is Outcome.Failed -> siError = signInNotice(r.problem, host)
            }
        }
    }

    /** What the key is called in the dashboard's list of keys. */
    private fun keyName() = "Crossfyre Mobile: ${Build.MODEL}"

    private fun signedInAs(s: SignedIn, via: String) {
        store.saveSignIn(s)
        store.signedInWith = via
        signedInWith = via
        user = store.user()
        revoked = false
        say("Signed in as ${s.user.username.ifEmpty { s.user.email }}")
        openWorkspaces(back = false)
    }

    fun changeOrigin(raw: String): Boolean {
        val normal = Pairing.normaliseApiUrl(raw) ?: return false
        origin = normal
        store.saveOrigin(normal)
        return true
    }

    // Browser sign-in.
    var deviceStatus by mutableStateOf(DeviceStatus.OPENING)
        private set
    var deviceCode by mutableStateOf("")
        private set
    var deviceUrl by mutableStateOf("")
        private set
    var deviceDeadline by mutableStateOf(0L)
        private set
    var deviceError by mutableStateOf<Notice?>(null)
        private set
    private var deviceJob: Job? = null

    val clientInfo: ClientInfo
        get() = ClientInfo(
            hostname = Build.MODEL,
            os = "Android ${Build.VERSION.RELEASE}",
            version = BuildConfig.VERSION_NAME,
        )

    fun browserSignIn() {
        deviceJob?.cancel()
        route = Route.DEVICE
        deviceStatus = DeviceStatus.OPENING
        deviceError = null
        deviceJob = viewModelScope.launch {
            val api = api()
            val started = withContext(Dispatchers.IO) { api.startDeviceLogin(clientInfo) }
            if (started is Outcome.Failed) {
                deviceError = deviceStartNotice(started.problem, host)
                deviceStatus = DeviceStatus.ERROR
                return@launch
            }
            val login: DeviceLogin = (started as Outcome.Ok).value
            deviceCode = login.deviceCode
            deviceUrl = login.approvalUrl
            deviceDeadline = SystemClock.elapsedRealtime() + login.expiresInSeconds * 1000L
            deviceStatus = DeviceStatus.WAITING
            emit(Effect.OpenUrl(login.approvalUrl))
            // The poll is a blocking network call, so the whole wait runs off the
            // main thread; only the answer comes back to it.
            val result = withContext(Dispatchers.IO) {
                awaitApproval(
                    login,
                    poll = { code -> api.pollDeviceLogin(code) },
                    sleep = { ms -> delay(ms) },
                    now = { SystemClock.elapsedRealtime() },
                )
            }
            when (result) {
                is Outcome.Ok -> {
                    if (route == Route.DEVICE) signedInAs(result.value, "browser")
                }
                is Outcome.Failed -> deviceStatus = when {
                    result.problem == Problem.Declined -> DeviceStatus.DENIED
                    result.problem == Problem.Expired -> DeviceStatus.EXPIRED
                    // The server no longer knows the code, which is what a lapsed request looks like.
                    reasonOf(result.problem) == io.crossfyre.mobile.account.Refusal.UNKNOWN -> DeviceStatus.EXPIRED
                    else -> {
                        deviceError = deviceStartNotice(result.problem, host)
                        DeviceStatus.ERROR
                    }
                }
            }
        }
    }

    fun reopenApproval() {
        if (deviceUrl.isNotEmpty()) emit(Effect.OpenUrl(deviceUrl))
    }

    fun cancelDevice() {
        deviceJob?.cancel()
        deviceJob = null
        route = Route.SIGN_IN
    }

    // ── Workspaces ───────────────────────────────────────────────────────────

    var wsStatus by mutableStateOf(ListStatus.LOADING)
        private set
    var wsTrouble by mutableStateOf<ListTrouble?>(null)
        private set
    var wsNotice by mutableStateOf<Notice?>(null)
        private set
    var workspaces by mutableStateOf<List<Workspace>>(emptyList())
        private set
    var wsSel by mutableStateOf<String?>(null)
    var wsBusy by mutableStateOf(false)
        private set
    var wsError by mutableStateOf<Notice?>(null)
    var wsBack by mutableStateOf(false)
        private set

    fun openWorkspaces(back: Boolean) {
        wsBack = back
        wsError = null
        route = Route.WORKSPACES
        loadWorkspaces()
    }

    fun loadWorkspaces() {
        val key = store.key() ?: return signedOut()
        wsStatus = ListStatus.LOADING
        viewModelScope.launch {
            when (val r = withContext(Dispatchers.IO) { api().workspaces(key) }) {
                is Outcome.Ok -> {
                    workspaces = r.value
                    wsStatus = if (r.value.isEmpty()) ListStatus.EMPTY else ListStatus.READY
                    val current = workspace?.id
                    wsSel = when {
                        wsBack && current != null && r.value.any { it.id == current } -> current
                        wsSel != null && r.value.any { it.id == wsSel } -> wsSel
                        else -> r.value.firstOrNull { it.isActive }?.id ?: r.value.firstOrNull()?.id
                    }
                }
                is Outcome.Failed -> {
                    if (r.problem == Problem.SignedOut) return@launch signedOut()
                    wsTrouble = listTrouble(r.problem)
                    wsNotice = listNotice(r.problem, host)
                    wsStatus = ListStatus.ERROR
                }
            }
        }
    }

    /** The list said there was nothing; it reloads when the person comes back from the dashboard. */
    fun onResumed() {
        if (route == Route.WORKSPACES && wsStatus == ListStatus.EMPTY) loadWorkspaces()
        refreshCert()
        refreshNotifications()
        if (route == Route.MAIN) refreshPatchStates()
    }

    fun pairSelected() {
        val id = wsSel ?: return
        val w = workspaces.firstOrNull { it.id == id } ?: return
        val key = store.key() ?: return signedOut()
        if (wsBusy) return
        wsBusy = true
        wsError = null
        viewModelScope.launch {
            // A different session is about to get this phone's traffic, so the old
            // one stops first rather than carrying on under a token being replaced.
            if (running) stopCapture()
            val r = withContext(Dispatchers.IO) { api().pair(key, w.id, store.deviceId(), Build.MODEL) }
            wsBusy = false
            when (r) {
                is Outcome.Ok -> {
                    Pairing.persist(ctx, r.value.pairing)
                    pairing = r.value.pairing
                    store.pairedFromAccount = true
                    val chosen = ChosenWorkspace(w.id, r.value.workspaceName.ifEmpty { w.name }, w.ownerKind, w.org.orEmpty())
                    store.saveWorkspace(chosen)
                    workspace = chosen
                    sessionName = r.value.sessionName
                    session.paired()
                    qrEnded = false
                    revoked = false
                    route = Route.MAIN
                    tab = "home"
                    push = null
                    say("Paired with ${chosen.name}")
                }
                is Outcome.Failed -> {
                    if (r.problem == Problem.SignedOut) return@launch signedOut()
                    wsError = pairNotice(r.problem, host)
                }
            }
        }
    }

    /** The key no longer works. Everything the account gave the phone goes; the device things stay. */
    private fun signedOut() {
        if (running) stopCapture()
        store.signOut()
        Pairing.clear(ctx)
        pairing = null
        workspace = null
        user = null
        signedInWith = null
        route = Route.SIGN_IN
        say("You have been signed out. Sign in again.", R.drawable.ic_info)
    }

    fun signOut() {
        overlay = null
        val key = store.key()
        if (running) stopCapture()
        // Revoke on the server as well, so signing a lost phone out is not only
        // local. Best effort: a phone with no signal still signs out here.
        if (key != null) viewModelScope.launch(Dispatchers.IO) { api().logout(key) }
        store.signOut()
        Pairing.clear(ctx)
        pairing = null
        workspace = null
        user = null
        signedInWith = null
        revoked = false
        route = Route.SIGN_IN
        tab = "home"
        push = null
        say("Signed out. This phone's key was revoked.")
    }

    /** "Sign in again" after a revoked key, or "Sign in" from a QR pairing: back to the front door. */
    fun toSignIn() {
        if (revoked || signedIn) {
            if (running) stopCapture()
            store.signOut()
            Pairing.clear(ctx)
            pairing = null
            workspace = null
            user = null
            signedInWith = null
            revoked = false
        }
        route = Route.SIGN_IN
        tab = "home"
        push = null
        overlay = null
    }

    fun unpair() {
        overlay = null
        if (running) stopCapture()
        Pairing.clear(ctx)
        pairing = null
        store.saveWorkspace(null)
        store.pairedFromAccount = false
        workspace = null
        push = null
        if (signedIn) {
            wsSel = null
            openWorkspaces(back = false)
        } else {
            route = Route.SIGN_IN
        }
        say("Unpaired. Capture stopped.", R.drawable.ic_info)
    }

    // ── Pairing ──────────────────────────────────────────────────────────────

    var pairing by mutableStateOf(Pairing.load(app))
        private set
    var workspace by mutableStateOf(store.workspace())
        private set
    var sessionName by mutableStateOf("Crossfyre Mobile: ${Build.MODEL}")
        private set
    val fromAccount: Boolean get() = store.pairedFromAccount && pairing != null && signedIn

    /** A QR pairing whose session ended when capture stopped. */
    var qrEnded by mutableStateOf(false)
        private set
    private val session = SessionState()

    /** Where the requests go, as the card names it. */
    val destination: String get() = if (fromAccount) workspace?.name ?: "your workspace" else "your workspace"

    /** The server the pairing ships to, which for a QR pairing is the code's. */
    val pairingHost: String get() = pairing?.let { displayHost(it.apiUrl) } ?: host

    fun scan() {
        overlay = null
        emit(Effect.Scan)
    }

    fun scanned(payload: String) {
        val parsed = Pairing.parseQr(payload)
        overlay = if (parsed == null) Overlay.PairInvalid else Overlay.PairConfirm(parsed)
    }

    fun confirmPairing(p: Pairing) {
        overlay = null
        if (running) stopCapture()
        Pairing.persist(ctx, p)
        pairing = p
        store.pairedFromAccount = false
        store.saveWorkspace(null)
        workspace = null
        qrEnded = false
        route = Route.MAIN
        tab = "home"
        push = null
        say("Paired with a Web Tracer session on ${displayHost(p.apiUrl)}")
    }

    fun sessionUrl(): String {
        val p = pairing ?: return "$origin/home"
        return "${p.apiUrl}/home/ops/workflows/web-tracer/view/${p.workflowId}"
    }

    fun openDashboard() = emit(Effect.OpenUrl(sessionUrl()))
    fun openUrl(url: String) = emit(Effect.OpenUrl(url))

    // ── Capture ──────────────────────────────────────────────────────────────

    var phase by mutableStateOf(Phase.IDLE)
        private set
    val running: Boolean get() = phase != Phase.IDLE || TracerVpnService.active
    var startFailed by mutableStateOf(false)
        private set
    /** The service's own account of why the last start failed, when it gave one. */
    var failMessage by mutableStateOf<String?>(null)
        private set
    var startError by mutableStateOf<Notice?>(null)
        private set
    internal var stats by mutableStateOf<Stats?>(null)
        private set
    var recent by mutableStateOf<List<RecentRequest>>(emptyList())
        private set
    var since by mutableStateOf(0L)
        private set
    var notificationsBlocked by mutableStateOf(false)
        private set
    var renewing by mutableStateOf(false)
        private set
    private val watch = StartWatch()
    private var wasActive = false

    var scopeMode by mutableStateOf(Scope.ALL)
    val scopeApps = mutableStateListOf<String>()
    val scope: Scope get() = Scope(scopeMode, scopeApps.toList())
    var scopeQuery by mutableStateOf("")
    var fullCapture by mutableStateOf(FullCapturePrefs.allowed(app))
        private set
    private var preflightAcknowledged = false

    private fun boot() {
        val (mode, apps) = ScopePrefs.load(ctx)
        scopeMode = mode
        scopeApps.addAll(apps.sorted())
        route = when {
            pairing != null -> Route.MAIN
            user != null -> Route.WORKSPACES
            else -> Route.SIGN_IN
        }
        qrEnded = pairing != null && !store.pairedFromAccount && Pairing.ended(ctx) && !TracerVpnService.active
        if (route == Route.WORKSPACES) loadWorkspaces()
        if (TracerVpnService.active) {
            // The foreground service kept the process alive while the app was
            // closed, so this is a capture that is really running.
            phase = Phase.CAPTURING
            wasActive = true
            session.paired()
        }
        viewModelScope.launch(Dispatchers.IO) { patch.tidy() }
        refreshCert()
        checkKey()
    }

    /**
     * Find out whether the account key still works. Nothing changes on the
     * phone when a key is revoked in the dashboard until the phone next uses it,
     * which is on opening and at the next start.
     */
    private fun checkKey() {
        val key = store.key() ?: return
        viewModelScope.launch {
            val r = withContext(Dispatchers.IO) { api().verifyKey(key) }
            if (r is Outcome.Failed && r.problem == Problem.SignedOut) revoked = true
        }
    }

    fun persistScope() = ScopePrefs.save(ctx, scopeMode, scopeApps.toSet())

    fun toggleScopeApp(pkg: String) {
        if (scopeApps.contains(pkg)) scopeApps.remove(pkg) else scopeApps.add(pkg)
        persistScope()
    }

    fun chooseScopeMode(mode: String) {
        scopeMode = mode
        persistScope()
    }

    fun openScope() {
        if (phase != Phase.IDLE) say("Stop capture to change the scope.", R.drawable.ic_info)
        else {
            loadApps()
            overlay = Overlay.Scope
        }
    }

    fun toggleFull() {
        when {
            phase != Phase.IDLE -> say("Stop capture to change this.", R.drawable.ic_info)
            fullCapture -> {
                fullCapture = false
                FullCapturePrefs.set(ctx, false)
            }
            else -> overlay = Overlay.FullConsent
        }
    }

    fun allowFull() {
        fullCapture = true
        FullCapturePrefs.set(ctx, true)
        overlay = null
    }

    /** The polling loop: what the service reached, the counters, and the kept requests. Runs while the app is in front. */
    suspend fun poll() {
        while (true) {
            val live = TracerVpnService.active
            val now = SystemClock.elapsedRealtime()
            phase = watch.phase(live, now)
            startFailed = watch.failed || failMessage != null
            TracerVpnService.failure?.let { why ->
                // The service gave up and said why: no need to wait out the grace.
                if (!live) {
                    watch.stopped()
                    phase = Phase.IDLE
                    failMessage = why
                    startFailed = true
                }
                TracerVpnService.failure = null
            }
            if (live) since = TracerVpnService.startedAt
            if (wasActive && !live) {
                // Stopped from the notification, or by Android: the session ended.
                session.ended()
                if (!fromAccount && pairing != null) qrEnded = true
            }
            wasActive = live
            if (live) {
                stats = withContext(Dispatchers.Default) { runCatching { Stats.parse(Native.captureStats()) }.getOrNull() }
            } else if (phase == Phase.IDLE) {
                stats = null
            }
            recent = withContext(Dispatchers.Default) {
                runCatching { RecentRequest.parseList(Native.recentRequests()) }.getOrDefault(recent)
            }
            delay(if (live || phase == Phase.STARTING) 500 else 1500)
        }
    }

    fun refreshNotifications() {
        notificationsBlocked = Build.VERSION.SDK_INT >= 33 &&
            !NotificationManagerCompat.from(ctx).areNotificationsEnabled()
    }

    /** "On", "Off" or "Not asked yet", for Settings. */
    val notificationState: String
        get() = when {
            !NotificationManagerCompat.from(ctx).areNotificationsEnabled() -> if (prefs.notificationsAsked || Build.VERSION.SDK_INT < 33) "Off" else "Not asked yet"
            else -> "On"
        }

    fun onStartTapped() {
        startError = null
        failMessage = null
        continueStart()
    }

    /** Walk the gates in [nextStartStep]'s order, stopping at the first that needs an answer. */
    fun continueStart() {
        val warnings = preflightWarnings()
        val step = nextStartStep(
            disclosed = prefs.disclosed,
            preflightWarnings = warnings.isNotEmpty(),
            preflightAcknowledged = preflightAcknowledged,
            notificationsToAsk = Build.VERSION.SDK_INT >= 33 && !prefs.notificationsAsked &&
                !NotificationManagerCompat.from(ctx).areNotificationsEnabled(),
            vpnConsentNeeded = VpnService.prepare(ctx) != null,
        )
        when (step) {
            StartStep.DISCLOSE -> overlay = Overlay.Disclosure
            StartStep.PREFLIGHT -> overlay = Overlay.Preflight(warnings)
            StartStep.NOTIFICATIONS -> {
                overlay = null
                emit(Effect.AskNotifications)
            }
            StartStep.VPN -> {
                overlay = null
                VpnService.prepare(ctx)?.let { emit(Effect.AskVpn(it)) }
            }
            StartStep.START -> {
                overlay = null
                preflightAcknowledged = false
                launchCapture()
            }
        }
    }

    fun agreeDisclosure() {
        prefs.disclosed = true
        continueStart()
    }

    /** "Not now": nothing starts, and the disclosure is shown again at the next Start. */
    fun declineDisclosure() {
        overlay = null
        say("Capture is off. Start it from the Tracer whenever you're ready.", R.drawable.ic_info)
    }

    fun startAnyway() {
        preflightAcknowledged = true
        continueStart()
    }

    fun notificationsAnswered() {
        prefs.notificationsAsked = true
        refreshNotifications()
        continueStart()
    }

    fun vpnAnswered(granted: Boolean) {
        if (granted) continueStart()
        else say("Capture needs the VPN connection, so nothing was started.", R.drawable.ic_info)
    }

    private fun launchCapture() {
        viewModelScope.launch {
            // Make the certificate on disk the one capture presents. The native
            // side keeps the last one it loaded in memory, and after a reset that
            // would otherwise be the old certificate until the app restarted.
            withContext(Dispatchers.IO) { runCatching { Native.generateCaPem() } }
            refreshCert()
            // A signed-in phone renews an ended session by pairing again, which
            // mints a new token. Never under a running patch, which uses the
            // current one.
            if (session.mustRepair(inUse = patch.job.value?.running == true, renewable = fromAccount)) {
                val key = store.key()
                val ws = workspace
                if (key == null || ws == null) {
                    startError = Notice(Level.DANGER, "Capture did not start.", "This phone has no workspace to send to. Pick one in Settings.")
                    return@launch
                }
                renewing = true
                val r = withContext(Dispatchers.IO) { api().pair(key, ws.id, store.deviceId(), Build.MODEL) }
                renewing = false
                when (r) {
                    is Outcome.Ok -> {
                        Pairing.persist(ctx, r.value.pairing)
                        pairing = r.value.pairing
                        sessionName = r.value.sessionName.ifEmpty { sessionName }
                        session.paired()
                    }
                    is Outcome.Failed -> {
                        if (r.problem == Problem.SignedOut) {
                            revoked = true
                        } else {
                            startError = Notice(Level.DANGER, "Capture did not start.", pairNotice(r.problem, pairingHost).let { "${it.title} ${it.body}" })
                        }
                        return@launch
                    }
                }
            }
            persistScope()
            refreshNotifications()
            TracerVpnService.failure = null
            failMessage = null
            watch.asked(SystemClock.elapsedRealtime())
            phase = Phase.STARTING
            ctx.startService(
                Intent(ctx, TracerVpnService::class.java)
                    .setAction(TracerVpnService.ACTION_START)
                    .putExtra(TracerVpnService.EXTRA_MODE, scopeMode)
                    .putExtra(TracerVpnService.EXTRA_APPS, scopeApps.toTypedArray())
            )
        }
    }

    fun stopCapture() {
        ctx.startService(Intent(ctx, TracerVpnService::class.java).setAction(TracerVpnService.ACTION_STOP))
        watch.stopped()
        phase = Phase.IDLE
        session.ended()
        if (!fromAccount && pairing != null) qrEnded = true
        wasActive = false
    }

    /** The diagnosis's button. */
    fun diagAction(a: DiagAction) {
        when (a) {
            DiagAction.OPEN_DASHBOARD -> openDashboard()
            DiagAction.SCAN_NEW_CODE -> scan()
            // Pairing again mints a new token and retires the old one, which is
            // only safe with nothing using it: stop, then start, which pairs.
            DiagAction.PAIR_AGAIN -> {
                stopCapture()
                say("Pairing again with a new session token.", R.drawable.ic_info)
                onStartTapped()
            }
        }
    }

    fun diagnosis(): Diag? {
        if (phase != Phase.CAPTURING) return null
        val inScope = if (scope.effectiveMode == Scope.ONLY) scopeApps.toList() else emptyList()
        return diagnose(
            running = true,
            s = stats,
            patchedInScope = inScope.any { patchStates[it] == PatchState.CURRENT },
            flutterInScope = inScope.any { facts[it]?.flutter == true },
            patching = patch.available,
            renewable = fromAccount,
            host = pairingHost,
        )
    }

    /** Apps in an "only" scope that will not decrypt, by name. */
    private fun preflightWarnings(): List<String> {
        if (!patch.available || scope.effectiveMode != Scope.ONLY) return emptyList()
        return scopeApps.filter { patchStates[it] == PatchState.STALE }.map { labelOf(it) }
    }

    // ── Apps ─────────────────────────────────────────────────────────────────

    var apps by mutableStateOf<List<InstalledApp>?>(null)
        private set
    val facts = mutableStateMapOf<String, AppFacts>()
    val patchStates = mutableStateMapOf<String, PatchState>()
    private var appsJob: Job? = null

    fun labelOf(pkg: String): String = apps?.firstOrNull { it.pkg == pkg }?.label ?: facts[pkg]?.label ?: pkg

    /** List the apps once, then read each one in the background, the ones in scope first. */
    fun loadApps(force: Boolean = false) {
        if (appsJob?.isActive == true) return
        if (apps != null && !force) return
        appsJob = viewModelScope.launch {
            val list = withContext(Dispatchers.IO) { Apps.installed(ctx) }
            apps = list
            refreshPatchStates()
            val ordered = list.sortedByDescending { scopeApps.contains(it.pkg) }
            for (a in ordered) {
                if (facts.containsKey(a.pkg)) continue
                val f = withContext(Dispatchers.IO) { runCatching { Apps.read(ctx, a.pkg, a.label) }.getOrNull() }
                if (f != null) facts[a.pkg] = f
            }
        }
    }

    /** Read one app now, for its details screen. */
    fun loadFacts(pkg: String) {
        if (facts.containsKey(pkg)) return
        viewModelScope.launch {
            val label = labelOf(pkg).takeIf { it != pkg } ?: withContext(Dispatchers.IO) { Apps.label(ctx, pkg) }
            val f = withContext(Dispatchers.IO) { runCatching { Apps.read(ctx, pkg, label) }.getOrNull() }
            if (f != null) facts[pkg] = f
        }
    }

    fun refreshPatchStates() {
        if (!patch.available) return
        viewModelScope.launch {
            val ca = cert.fingerprint
            val pkgs = (apps?.map { it.pkg }.orEmpty() + scopeApps).distinct()
            val states = withContext(Dispatchers.IO) { pkgs.associateWith { patch.state(it, ca) } }
            patchStates.putAll(states)
            staleCount = withContext(Dispatchers.IO) { patch.stale(ca) }
            patchedCount = withContext(Dispatchers.IO) { patch.patchedCount() }
        }
    }

    var staleCount by mutableStateOf<List<String>>(emptyList())
        private set
    var patchedCount by mutableStateOf(0)
        private set

    var patchQuery by mutableStateOf("")

    fun openApp(pkg: String) {
        overlay = null
        loadFacts(pkg)
        push = Push.App(pkg)
    }

    fun startPatch(pkg: String) {
        val p = pairing ?: return say("Pair a workspace first.", R.drawable.ic_info)
        if (qrEnded) return say("This pairing code has been used. Scan a new one first.", R.drawable.ic_info)
        viewModelScope.launch {
            val ca = withContext(Dispatchers.IO) { ensureCaFile() }
            if (ca == null) return@launch say("Could not create this phone's certificate.", R.drawable.ic_warning)
            refreshCert()
            val f = facts[pkg]
            patch.start(pkg, f?.label ?: labelOf(pkg), f?.sizeMb ?: 0, p, ca, cert.fingerprint)
        }
    }

    fun cancelPatch() {
        patch.cancel()
        say("Patch cancelled. Nothing was installed or changed.", R.drawable.ic_info)
    }

    fun patchFinished() {
        patch.dismiss()
        refreshPatchStates()
    }

    fun exportPatched() {
        val pkg = patch.exportable.value ?: return
        val name = labelOf(pkg).lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-').ifEmpty { "app" }
        emit(Effect.ExportApk("$name-patched.apk"))
    }

    // ── Certificate ──────────────────────────────────────────────────────────

    var cert by mutableStateOf(CertInfo(false, null, 0L, false))
        private set
    var chromeHelp by mutableStateOf(false)

    private val caPem get() = File(ctx.filesDir, "ca.pem")

    /**
     * Filename for the exported certificate, suffixed per environment: all
     * three builds can be installed at once and each has a different
     * certificate, and three identical files in Downloads is how the dev one
     * gets imported by mistake.
     */
    val caFileName: String
        get() = when (env) {
            "prod" -> "crossfyre-ca.crt"
            else -> "crossfyre-ca-$env.crt"
        }

    fun refreshCert() {
        viewModelScope.launch {
            cert = withContext(Dispatchers.IO) { readCert() }
            if (patch.available && route == Route.MAIN) refreshPatchStates()
        }
    }

    /**
     * Read straight off disk rather than through `generateCaPem()`, which MINTS
     * a certificate when none exists. Asking which certificate this is must
     * never be the thing that creates one.
     */
    private fun readCert(): CertInfo {
        val f = caPem
        if (!f.exists()) return CertInfo(false, null, 0L, false)
        val der = runCatching {
            val pem = f.readText()
            java.util.Base64.getMimeDecoder().decode(
                pem.substringAfter("-----BEGIN CERTIFICATE-----").substringBefore("-----END CERTIFICATE-----")
            )
        }.getOrNull() ?: return CertInfo(false, null, 0L, false)
        val fp = java.security.MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) }
        return CertInfo(true, fp, f.lastModified(), inAndroidStore(der))
    }

    /** Whether Android's user trust store holds this certificate. Readable without any permission. */
    private fun inAndroidStore(der: ByteArray): Boolean = runCatching {
        val ks = java.security.KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        ks.aliases().toList().any { alias ->
            alias.startsWith("user:") && ks.getCertificate(alias)?.encoded?.contentEquals(der) == true
        }
    }.getOrDefault(false)

    /**
     * The certificate as a file a patch can upload, made if the phone has none.
     * Patching does not need the certificate installed in Android, so it must
     * not need the button that installs it either.
     */
    private fun ensureCaFile(): File? {
        val pem = runCatching { Native.generateCaPem() }.getOrNull() ?: return null
        if (pem.startsWith("ERROR")) return null
        val out = File(ctx.getExternalFilesDir(null) ?: ctx.filesDir, caFileName)
        return runCatching { out.writeText(pem); out }.getOrNull()
    }

    /** The certificate's PEM for saving, made if the phone has none yet. */
    fun caPemForSaving(): String? {
        val pem = runCatching { Native.generateCaPem() }.getOrNull() ?: return null
        return pem.takeUnless { it.startsWith("ERROR") }
    }

    fun saveCertificate() = emit(Effect.SaveCa(caFileName))

    fun certSaved(ok: Boolean) {
        refreshCert()
        say(if (ok) "Saved $caFileName" else "Save cancelled.", if (ok) R.drawable.ic_check_circle else R.drawable.ic_info)
    }

    /**
     * Destroy the certificate and forget every patch made with it.
     *
     * A trusted CA whose private key is still on the phone should not outlive
     * the person's intent, so this exists; it is its own deliberate action,
     * apart from unpairing, because it is the only one that can state what it
     * will break.
     */
    fun resetCertificate() {
        if (running) stopCapture()
        runCatching { caPem.delete() }
        runCatching { File(ctx.filesDir, "ca.key").delete() }
        runCatching { File(ctx.getExternalFilesDir(null), caFileName).delete() }
        patch.forgetAll()
        overlay = Overlay.RemoveOldCert
        refreshCert()
    }

    fun securitySettings() {
        overlay = null
        emit(Effect.SecuritySettings)
    }

    fun notificationSettings() = emit(Effect.NotificationSettings)

    // ── Appearance ───────────────────────────────────────────────────────────

    var appearance by mutableStateOf(prefs.appearance)
        private set

    fun setAppearanceKey(key: String) {
        appearance = key
        prefs.appearance = key
    }

    // Last, so every property above is initialised before anything reads it.
    init {
        boot()
    }
}
