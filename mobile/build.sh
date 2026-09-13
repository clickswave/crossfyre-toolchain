#!/usr/bin/env bash
# Build the Crossfyre mobile tracer APK end to end: cross-compile the Rust native core (reusing the
# shared cfx_capture crate) with cargo-ndk into jniLibs, then assemble the APK with gradle.
#
# Prereqs: Android SDK + NDK, cargo-ndk, rust android targets, JDK 17.
# For a signed RELEASE build use `manager.sh build-mobile` instead; this is the
# quick debug loop.
#   ANDROID_HOME, ANDROID_NDK_HOME, JAVA_HOME set (or edit below).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
: "${ANDROID_HOME:=$HOME/Android/Sdk}"
: "${ANDROID_NDK_HOME:=$ANDROID_HOME/ndk/27.2.12479018}"
: "${JAVA_HOME:=/usr/lib/jvm/java-17-openjdk}"
export ANDROID_HOME ANDROID_NDK_HOME JAVA_HOME

echo "[1/2] cross-compiling native core (cfx_mobile) -> jniLibs"
( cd "$here/rust" && cargo ndk -t arm64-v8a -o "$here/app/src/main/jniLibs" build --release )

echo "[2/2] assembling APK"
# Use the wrapper, not a system gradle: it pins the version and verifies the
# distribution checksum, which a system install does not.
( cd "$here" && ./gradlew :app:assembleDebug --no-daemon --console=plain )
echo "APK -> app/build/outputs/apk/debug/app-debug.apk"
