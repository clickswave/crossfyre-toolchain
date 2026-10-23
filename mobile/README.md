# Crossfyre Mobile (Android)

Crossfyre Mobile captures the HTTP and HTTPS requests that apps on your phone
make, so you can test apps you own or are authorized to test, without a
computer and without root. It runs as an Android `VpnService` on the phone,
reads each request, sends it on to where it was going, and sends a record of it
to your [Crossfyre](https://crossfyre.io) workspace, where it lands in the same
Requests table and asset graph as traffic captured anywhere else.

It is built on the `cfx_capture` crate in this repository, the same capture
engine the desktop Web Tracer uses. Until version 0.2.0 the app was called
Crossfyre Tracer.

## What it does to your phone

This app decrypts traffic. You should want a precise account of that before
installing it, so here is one. The app shows the same account on its own
screen before the first capture, and asks you to agree before Android's VPN
prompt appears.

- **A certificate made on the phone.** The app generates a CA certificate on
  the device. Its private key never leaves the phone.
- **A VPN that stays on the phone.** Android routes the traffic of the apps in
  scope through this app. Nothing is tunnelled to a remote VPN server, and the
  phone's address and location do not change.
- **HTTPS read only where an app allows it.** For each connection the app
  presents a certificate made from its CA. An app that trusts that certificate
  is read; one that does not refuses the connection, and the app says so.
- **Sent to your workspace.** For each request, the method, host, path and
  status are sent over HTTPS to the workspace you paired with. Query values,
  header values and bodies stay on the phone unless you turn on
  **Send full requests**, which asks first and stays off until you do.
- **You choose the scope.** Scope starts as the whole phone. Narrow it to
  chosen apps, or exclude some, before starting. The app never captures itself.
- **It says when it is running.** A notification with a Stop button shows for
  as long as capture runs, and Android shows its key icon in the status bar.

If any of that is not what you want, do not install it. The source is here so
you can check the description against the code rather than trust it.

## Two builds

| Build | Where it comes from | Patch a pinned app |
|---|---|---|
| `direct` | the APK on crossfyre.io, signed with our release key | yes |
| `play` | Google Play, signed by Play App Signing | no |

The Play build is compiled without the patch feature, not with it hidden. Its
code lives in `app/src/direct`, which the Play build does not include, and so do
the permissions only patching needs (`REQUEST_INSTALL_PACKAGES`,
`REQUEST_DELETE_PACKAGES`). Play restricts installing packages to a short list
of app categories, and rewriting another app is not one of them.

Neither build asks for `QUERY_ALL_PACKAGES`. The scope list offers the apps that
have a launcher icon, through a `<queries>` filter for exactly those.

Both builds share an application id but are signed by different keys, so one
cannot update the other. Moving between them means uninstalling first, which
also removes the app's certificate and pairing.

## Three environments

Each environment is its own app, so all three can be installed side by side,
each with its own certificate.

| Flavour | Application id | Name | Server |
|---|---|---|---|
| `prod` | `io.crossfyre.mobile` | Crossfyre Mobile | https://crossfyre.io |
| `staging` | `io.crossfyre.mobile.staging` | Crossfyre Mobile Staging | https://staging.crossfyre.io |
| `dev` | `io.crossfyre.mobile.dev` | Crossfyre Mobile Dev | `http://10.0.2.2:12004` |

Only the dev build can change its server, on the sign-in screen, because a dev
stack's address on a LAN moves around. Only the dev build accepts plain http,
and only to a loopback or private address. The emulator reaches the host
computer at `10.0.2.2`.

## Signing in and pairing

There are three ways to connect the phone to a workspace:

- **Password.** A username or email and a password, the same account as the
  dashboard.
- **Browser.** The app opens the dashboard's approval page and waits while you
  approve the phone there. This is the only way in for an account made with
  Google, which has no password.
- **QR code.** Scan the pairing code shown in a Web Tracer session in the
  dashboard. This needs no account on the phone. The app shows the server the
  code points at and pairs only if you confirm it.

Signed in, you pick a workspace and the phone gets a Web Tracer session of its
own there, named after the phone. Stopping a capture ends that session, and the
next start renews it on its own. A QR pairing lasts for one capture; after that
the app asks for a new code.

The account key is kept encrypted under a key held by the Android keystore.
Signing out revokes it on the server as well as forgetting it on the phone. The
certificate and any patched apps are device things and stay.

## Certificate-pinned apps

Pinned apps reject even a trusted certificate, so they do not work under capture
by default. The direct build can patch one: the app uploads it to a hosted
service that rebuilds it to trust this phone's certificate, then reinstalls it.
See [tools/README-pinned-apps.md](tools/README-pinned-apps.md) for how that
works, what it costs, and what still does not work.

## Limits

- Since Android 7, apps ignore user-installed certificates unless they opt in.
  Chrome is one of them. Firefox can be told to trust them; most other apps
  cannot be read without patching (direct build) or root.
- Flutter apps carry their own TLS stack and ignore Android's certificate
  settings entirely. Unpatched, only their analytics traffic is readable.
- An app that checks its own signature or integrity installs once patched and
  then refuses to run. That needs root, which this app does not use.
- HTTP/3 cannot be read, so it is blocked and apps fall back to TCP. Some wait
  up to a minute before they do.
- The phone keeps the last 30 requests it captured, for its own list, until the
  next capture starts. The dashboard holds the rest.
- Using the phone as a node for scans is planned and not built. The Node tab
  says so and does nothing.

## Build

Prerequisites: Android SDK with build-tools and NDK, JDK 17, Rust with the
Android targets, and [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk). Gradle
fails on a newer JDK with nothing but the JDK's version number as its message,
so point `JAVA_HOME` at 17.

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk

# native core, both ABIs the app ships -> app/src/main/jniLibs
( cd rust && cargo ndk -t arm64-v8a -t x86_64 -o ../app/src/main/jniLibs build --release )

# a variant is one environment and one build, such as prodDirect or prodPlay
./gradlew :app:assembleProdDirectRelease
./gradlew :app:bundleProdPlayRelease

# unit tests, every variant
./gradlew :app:test
```

`build.sh` does the native step and a `devDirect` debug build in one go. The
gradle wrapper pins gradle 8.13 and verifies the distribution checksum.

Without a signing key the release builds are **unsigned**, which Android will
not install. That is deliberate: see `app/build.gradle.kts`.

## Reproducible builds

Two clean builds of the same commit produce byte-identical APK contents.

They do **not** produce identical file hashes, and that is expected: `apksigner`
signs RSA with a random PSS salt, so the signature differs every run. The
reproducibility identity is therefore a digest over the zip entries with the
signing block excluded, published as `contentSha256` alongside each release.

## Layout

| | |
|---|---|
| `rust/` | `cfx_mobile`, the JNI native core. A member of this repository's cargo workspace, depending on `capture/` |
| `app/src/main` | the app both builds share: the `VpnService`, the Compose screens, sign-in and pairing |
| `app/src/direct` | the patch feature, in the direct build only |
| `app/src/play` | the Play build's stand-in for it, which says it is not available |
| `app/src/test*` | unit tests, shared and per build |
| `tools/` | notes on capturing pinned apps, and `notices.py`, which writes the in-app licence notices |

## What is not in this repository

Rewriting an installed app so it accepts your certificate is done by a hosted
service, not on the device, and that service is not open source. Everything that
runs on your phone is here.

## Authorisation

Capture only traffic you are entitled to capture: your own device and your own
apps, or a target you are explicitly authorised to test. Interception and app
modification carry real legal weight in most jurisdictions and this tool does
not grant you any permission you do not already have.

## Licence

Apache-2.0, the same as the rest of this repository. The bundled fonts (Inter,
Outfit, JetBrains Mono, Orbitron) are under the SIL Open Font License 1.1 and
the icons (Phosphor) under MIT. The app lists every component it carries, with
its licence, under Settings > Open source licences.
