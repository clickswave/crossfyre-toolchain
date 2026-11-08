package io.crossfyre.mobile

import android.app.Application
import io.crossfyre.mobile.push.PushSetup

/** Starts Firebase before anything can need it: a push may start the process with no screen. */
class CrossfyreApp : Application() {
    override fun onCreate() {
        super.onCreate()
        PushSetup.start(this)
    }
}
