package io.crossfyre.tracer

/**
 * JNI bridge to the Rust native core (`cfx_mobile`), which reuses the shared `cfx_capture` crate -
 * the same session-CA + per-SNI MITM leaf + inspect/forward machinery the desktop Web Tracer uses.
 */
object Native {
    init {
        System.loadLibrary("cfx_mobile")
        initLogging()
    }

    /** Route Rust `log` output to logcat under the "cfx-mobile" tag. */
    external fun initLogging()

    /** Tell native the app-private dir where it may persist the CA (stable across restarts). */
    external fun setStorageDir(dir: String)

    /**
     * Generate a fresh session CA on-device and return its certificate PEM to install. The private
     * key stays in native memory and is reused by [startCapture].
     */
    external fun generateCaPem(): String

    /**
     * Start capturing: run the netstack over the VpnService TUN fd (MITM each flow via cfx_capture)
     * and ship events to `{apiUrl}/api/v1/web-trace/ingest` with the paired workflowId + token.
     * Returns true if capture started (requires a CA from [generateCaPem] first).
     */
    /**
     * @param allowFullCapture the DEVICE's answer to whether bodies and headers may be
     *   uploaded. The control plane can ask for full capture; it cannot grant it. Without
     *   this the server alone decided, while the app's own screen promised the opposite.
     */
    external fun startCapture(
        tunFd: Int,
        apiUrl: String,
        workflowId: String,
        token: String,
        allowFullCapture: Boolean
    ): Boolean

    /** Stop capturing and tear down the native runtime. Idempotent. */
    external fun stopCapture()

    /**
     * A JSON snapshot of the live capture counters (flows, tls_flows, ca_rejected, events,
     * ingest_sent, ingest_rejected, ingest_failed, last_event, last_error). Polled by the UI so the
     * user can see what capture is doing - and why nothing is showing up (a high `ca_rejected` with
     * zero `events` means the app in use does not trust the CA).
     */
    external fun captureStats(): String
}
