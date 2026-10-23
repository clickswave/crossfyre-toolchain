plugins {
    // 8.13 is the first plugin line that supports compileSdk 36. Play has required
    // new apps and updates to target 36 since 2026-08-31.
    id("com.android.application") version "8.13.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}
