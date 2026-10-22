import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ── Signing ──────────────────────────────────────────────────────────────────
//
// Two keys, one for each way the app is distributed.
//
// The RELEASE key signs the direct build, the APK people download and install
// themselves. THE SIGNING KEY IS PERMANENT. Android identifies an app by its
// signing certificate for the life of the install. Lose this keystore, or sign a
// later release with a different one, and every existing user has to uninstall
// and reinstall (losing their pairing) before they can update. Back it up in two
// places that are not this repository, and never commit it.
//
// The UPLOAD key signs the Play build. Play App Signing re-signs what reaches
// users with a key Google holds, so this one only proves that an upload came from
// us, and a lost upload key can be reset through Play support. It is still a
// credential and is never committed either.
//
// Credentials come from a gitignored keystore.properties at the repo root, or
// from the environment for CI. Both are checked so a developer can build
// without exporting anything and CI can build without a file on disk.
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) FileInputStream(keystorePropsFile).use { load(it) }
}

fun signingValue(prop: String, env: String): String? =
    (keystoreProps.getProperty(prop) ?: System.getenv(env))?.takeIf { it.isNotBlank() }

class KeySource(prop: String, env: String) {
    val storeFile = signingValue("${prop}storeFile", "${env}KEYSTORE")
    val storePassword = signingValue("${prop}storePassword", "${env}KEYSTORE_PASSWORD")
    val keyAlias = signingValue("${prop}keyAlias", "${env}KEY_ALIAS")
    val keyPassword = signingValue("${prop}keyPassword", "${env}KEY_PASSWORD")

    // All four or nothing. A partially configured keystore is a typo, not an
    // intention, and silently falling back to unsigned is how an uninstallable
    // build reaches a download page.
    val complete = listOf(storeFile, storePassword, keyAlias, keyPassword).all { it != null }
}

// keystore.properties: storeFile, storePassword, keyAlias, keyPassword for the
// release key, and the same four prefixed `upload.` for the upload key.
val releaseKey = KeySource("", "CROSSFYRE_ANDROID_")
val uploadKey = KeySource("upload.", "CROSSFYRE_ANDROID_UPLOAD_")

android {
    namespace = "io.crossfyre.mobile"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.crossfyre.mobile"
        minSdk = 26
        targetSdk = 36
        versionCode = 25
        versionName = "0.2.1"
        // arm64 for real devices, x86_64 for the emulator.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (releaseKey.complete) {
            create("release") {
                storeFile = file(releaseKey.storeFile!!)
                storePassword = releaseKey.storePassword
                keyAlias = releaseKey.keyAlias
                keyPassword = releaseKey.keyPassword
                // v2/v3 give fast verification and key rotation headroom. v1 stays
                // on for minSdk 26 breadth; it costs nothing and some sideload
                // paths still look for it.
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
        if (uploadKey.complete) {
            create("upload") {
                storeFile = file(uploadKey.storeFile!!)
                storePassword = uploadKey.storePassword
                keyAlias = uploadKey.keyAlias
                keyPassword = uploadKey.keyPassword
            }
        }
    }

    // Two dimensions. `env` is which control plane the app talks to, `dist` is how
    // it reaches a phone; every variant is one of each, such as devDirectDebug.
    //
    // env: one app per environment, installable side by side. Android keys an
    // installation by applicationId, so without a suffix the dev build replaces the
    // production one on the same phone: testing meant uninstalling the real app,
    // which also destroys its data, which means its CA and its pairing. A suffix
    // makes them three separate apps that happen to share a codebase.
    //
    // Each therefore keeps its OWN CA, in its own private storage, which is what
    // you want: a dev CA has no business being trusted for production traffic.
    // Within one flavour the CA is stable, because updates preserve app data as
    // long as the signing key does not change.
    //
    // dist: `direct` is the APK people install themselves, and it can patch a
    // pinned app. `play` is the Google Play build, compiled without the patch
    // feature: its source set (src/direct) is simply not part of the build, and
    // neither are the permissions only patching needs. Play restricts
    // REQUEST_INSTALL_PACKAGES, and rewriting other apps is a likely rejection.
    // Both share an applicationId, but they are signed by different keys (the
    // release key, and Play's app signing key), so one cannot update the other:
    // moving between them means uninstalling first.
    flavorDimensions += listOf("env", "dist")
    productFlavors {
        create("prod") {
            dimension = "env"
            // No suffix: production is the bare id.
            resValue("string", "app_name", "Crossfyre Mobile")
            buildConfigField("String", "DEFAULT_ORIGIN", "\"https://crossfyre.io\"")
            buildConfigField("boolean", "ORIGIN_EDITABLE", "false")
            buildConfigField("boolean", "LOCAL_HTTP", "false")
        }
        create("staging") {
            dimension = "env"
            applicationIdSuffix = ".staging"
            resValue("string", "app_name", "Crossfyre Mobile Staging")
            buildConfigField("String", "DEFAULT_ORIGIN", "\"https://staging.crossfyre.io\"")
            buildConfigField("boolean", "ORIGIN_EDITABLE", "false")
            buildConfigField("boolean", "LOCAL_HTTP", "false")
        }
        create("dev") {
            dimension = "env"
            applicationIdSuffix = ".dev"
            resValue("string", "app_name", "Crossfyre Mobile Dev")
            // The emulator reaches the host's loopback at 10.0.2.2. A phone uses the
            // dev box's LAN address instead, which changes with the network it is
            // on, so the dev build lets the server be edited on the sign-in screen.
            buildConfigField("String", "DEFAULT_ORIGIN", "\"http://10.0.2.2:12004\"")
            buildConfigField("boolean", "ORIGIN_EDITABLE", "true")
            // Every dev build talks to a dev stack over plain http on a private
            // address, release builds of it included. Production and staging never do.
            buildConfigField("boolean", "LOCAL_HTTP", "true")
        }
        create("direct") {
            dimension = "dist"
            buildConfigField("boolean", "PATCHING", "true")
            if (releaseKey.complete) signingConfig = signingConfigs.getByName("release")
        }
        create("play") {
            dimension = "dist"
            buildConfigField("boolean", "PATCHING", "false")
            if (uploadKey.complete) signingConfig = signingConfigs.getByName("upload")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // No signingConfig here: a build type's would override the dist
            // flavour's, and the two builds sign with different keys. Without a
            // configured key `assembleRelease` and `bundleRelease` still work, so a
            // build can be inspected locally, but the artifact is unsigned, and the
            // release checks refuse to stage one, so an unsigned build cannot reach
            // a download page or a Play upload by accident.
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    // buildConfig generates BuildConfig.DEBUG, which Pairing.normaliseApiUrl uses to
    // allow an http:// control plane on loopback and private ranges for the dev
    // stack while release builds require https, and the per-flavour fields above.
    // AGP 8 stopped generating it by default, so it has to be asked for.
    buildFeatures {
        compose = true
        buildConfig = true
    }
    testOptions {
        // Plain JVM tests of the account client and the pairing rules. Android
        // classes they touch in passing answer defaults instead of throwing.
        unitTests.isReturnDefaultValues = true
    }
    // The native lib is prebuilt into src/main/jniLibs by `cargo ndk` (see rust/). In CI this is a
    // gradle task that shells `cargo ndk -t arm64-v8a -t x86_64 -o app/src/main/jniLibs build --release`.
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.03")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    // Sign in with browser opens the approval page in a Custom Tab, which shares
    // the browser's cookies, so an account already signed in there approves in a tap.
    implementation("androidx.browser:browser:1.8.0")
    // QR pairing: CameraX for the preview and frames, and ZXing's core decoder for the
    // code. Only the core library: the embedded CaptureActivity had a black-preview bug
    // when locked to portrait. ZXing decodes on the phone with no service behind it,
    // which ML Kit did not: it brought Google's data transport services with it.
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")
    implementation("com.google.zxing:core:3.5.3")

    testImplementation("junit:junit:4.13.2")
    // android.jar's org.json is a stub in JVM tests; this is the real one.
    testImplementation("org.json:json:20240303")

    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
