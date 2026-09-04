import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ── Release signing ──────────────────────────────────────────────────────────
//
// There is no Play Store listing, so the APK is distributed directly and MUST
// carry our own signature: Android refuses to install an unsigned package.
//
// THE SIGNING KEY IS PERMANENT. Android identifies an app by its signing
// certificate for the life of the install. Lose this keystore, or sign a later
// release with a different one, and every existing user has to uninstall and
// reinstall (losing their pairing) before they can update. Back it up in two
// places that are not this repository, and never commit it.
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

val ksStoreFile = signingValue("storeFile", "CROSSFYRE_ANDROID_KEYSTORE")
val ksStorePassword = signingValue("storePassword", "CROSSFYRE_ANDROID_KEYSTORE_PASSWORD")
val ksKeyAlias = signingValue("keyAlias", "CROSSFYRE_ANDROID_KEY_ALIAS")
val ksKeyPassword = signingValue("keyPassword", "CROSSFYRE_ANDROID_KEY_PASSWORD")

// All four or nothing. A partially configured keystore is a typo, not an
// intention, and silently falling back to unsigned is how an uninstallable
// build reaches a download page.
val canSignRelease = listOf(ksStoreFile, ksStorePassword, ksKeyAlias, ksKeyPassword)
    .all { it != null }

android {
    namespace = "io.crossfyre.tracer"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.crossfyre.tracer"
        minSdk = 26
        targetSdk = 35
        versionCode = 9
        versionName = "0.1.8"
        // arm64 for real devices, x86_64 for the emulator.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    // One app per environment, installable side by side.
    //
    // Android keys an installation by applicationId, so without a suffix the dev
    // build replaces the production one on the same phone: testing meant
    // uninstalling the real app, which also destroys its data, which means its CA
    // and its pairing. A suffix makes them three separate apps that happen to
    // share a codebase.
    //
    // Each therefore keeps its OWN CA, in its own private storage, which is what
    // you want: a dev CA has no business being trusted for production traffic.
    // Within one flavour the CA is stable, because updates preserve app data as
    // long as the signing key does not change, and all three are signed by the
    // same release key.
    flavorDimensions += "env"
    productFlavors {
        create("prod") {
            dimension = "env"
            // No suffix: the production app keeps the identity it already has on
            // every phone that installed it. Changing it would orphan them.
            resValue("string", "app_name", "Crossfyre Tracer")
        }
        create("staging") {
            dimension = "env"
            applicationIdSuffix = ".staging"
            resValue("string", "app_name", "Crossfyre Tracer Staging")
        }
        create("dev") {
            dimension = "env"
            applicationIdSuffix = ".dev"
            resValue("string", "app_name", "Crossfyre Tracer Dev")
        }
    }

    signingConfigs {
        if (canSignRelease) {
            create("release") {
                storeFile = file(ksStoreFile!!)
                storePassword = ksStorePassword
                keyAlias = ksKeyAlias
                keyPassword = ksKeyPassword
                // v2/v3 give fast verification and key rotation headroom. v1 stays
                // on for minSdk 26 breadth; it costs nothing and some sideload
                // paths still look for it.
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Null when no keystore is configured. `assembleRelease` still works
            // so you can build and inspect locally, but the artifact is unsigned
            // and uninstallable; scripts/crossfyre_mobile.py refuses to publish
            // one, so an unsigned build cannot reach a download page by accident.
            signingConfig = if (canSignRelease) signingConfigs.getByName("release") else null
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    // buildConfig generates BuildConfig.DEBUG, which Pairing.normaliseApiUrl uses to
    // allow an http:// control plane on loopback and private ranges for the dev
    // stack while release builds require https. AGP 8 stopped generating it by
    // default, so it has to be asked for.
    buildFeatures {
        compose = true
        buildConfig = true
    }
    // The native lib is prebuilt into src/main/jniLibs by `cargo ndk` (see rust/). In CI this is a
    // gradle task that shells `cargo ndk -t arm64-v8a -o app/src/main/jniLibs build --release`.
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.03")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    // QR pairing: CameraX preview + ML Kit barcode scanning (reliable portrait scan; the zxing
    // embedded CaptureActivity had a black-preview bug when locked to portrait).
    implementation("androidx.camera:camera-camera2:1.3.4")
    implementation("androidx.camera:camera-lifecycle:1.3.4")
    implementation("androidx.camera:camera-view:1.3.4")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
}
