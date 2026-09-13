# Crossfyre Tracer (Android)

Crossfyre Tracer is an Android app that intercepts and inspects your device's
own HTTPS traffic, per-app or device-wide, without a computer and without root.
It runs as a `VpnService`, terminates TLS with a certificate it generates on the
device, and can forward what it sees to a [Crossfyre](https://crossfyre.io)
workspace.

It is the mobile half of the same capture engine the desktop Web Tracer uses:
both are built on the `cfx_capture` crate in this repository.

## What it actually does to your phone

This app decrypts your traffic. You should want a precise account of that before
installing it, so here is one.

- It generates a CA certificate **on the device**. The private key never leaves
  it. You install that CA yourself, through the system dialog.
- It starts a `VpnService`. Android routes traffic through it locally. **This is
  not a VPN**: nothing is tunnelled to a remote server by this mechanism, and
  the app declares no such capability.
- For each connection it presents a certificate minted from your CA, reads the
  plaintext, and forwards it to the real destination.
- Captured data is held on the device unless you pair it with a workspace. If
  you do, request and response metadata are sent to the control plane you paired
  with, which is a URL you supplied in the pairing QR. Nothing is sent anywhere
  else, and nothing is sent at all before you pair.
- Scope defaults to the whole device. Narrow it (**Scope → Only these**) before
  starting if you would rather it did not see everything.

If any of that is not what you want, do not install it. The source is here so
you can check the description against the code rather than trust it.

## Certificate-pinned apps

Pinned apps reject even a trusted CA's certificate, so they will not work under
interception by default. See [tools/README-pinned-apps.md](tools/README-pinned-apps.md)
for what can be done about that, what it costs, and what still will not work.

## Build

Prerequisites: Android SDK with build-tools, NDK, JDK 17, Rust with the Android
targets, and [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk).

```sh
rustup target add aarch64-linux-android
cargo install cargo-ndk

# native core -> app/src/main/jniLibs
( cd rust && cargo ndk -t arm64-v8a -o ../app/src/main/jniLibs build --release )

# the app
./gradlew :app:assembleRelease
```

The gradle wrapper pins gradle 8.10.2 and verifies the distribution checksum.
`build.sh` does the same two steps for a debug build.

Without a signing keystore the release build produces an **unsigned** APK, which
Android will not install. That is deliberate: see `app/build.gradle.kts`.

## Reproducible builds

Two clean builds of the same commit produce byte-identical APK contents.

They do **not** produce identical file hashes, and that is expected: `apksigner`
signs RSA with a random PSS salt, so the signature differs every run. The
reproducibility identity is therefore a digest over the zip entries with the
signing block excluded, published as `contentSha256` alongside each release.
This is the same comparison F-Droid makes when verifying that a developer-signed
APK really came from the published source.

## Layout

| | |
|---|---|
| `rust/` | `cfx_mobile`, the JNI native core. A member of this repository's cargo workspace, depending on `capture/` |
| `app/` | the Android app: `VpnService`, Compose UI, JNI bindings |
| `tools/` | notes on capturing pinned apps |

## What is not in this repository

Rewriting an installed app so it accepts your certificate is done by a hosted
service, not on the device, and that service is not open source. Everything that
runs on your phone is here.

## Authorisation

Intercept only traffic you are entitled to intercept: your own device and your
own apps, or a target you are explicitly authorised to test. Interception and
app modification carry real legal weight in most jurisdictions and this tool
does not grant you any permission you do not already have.

## Licence

Apache-2.0, the same as the rest of this repository.
