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
phone waits for the server to confirm first; when it cannot, the phone still
signs out, and the sign-in screen says to revoke the key in the dashboard under
Settings > CLI Access. The certificate and any patched apps are device things
and stay.

## Approving agent actions

An agent working with your Crossfyre account can be made to wait for you before
it does something that needs a person, such as a scan across more than one node
or requests that can change data on a target. The phone is where you say yes.

- **A key made on the phone.** Turning on Approvals in Settings makes a P-256
  signing key in the Android keystore. Its private half never leaves the phone.
  The app sends the public half to crossfyre.io with the phone's model name and
  install ID, and you confirm the phone once in a signed-in browser, which shows
  the same fingerprint as the phone. A phone with no screen lock cannot turn it on.
- **An unlock for every approval.** The keystore signs only after you unlock the
  phone: for each signature on Android 11 and later, and within fifteen seconds
  of the unlock on Android 8 to 10. What is signed is the SHA-256 of the exact
  request text the phone showed you, so the CLI or agent key on a computer cannot
  approve for you. Denying needs no unlock.
- **Only the phone approves.** A request goes to the person whose agent made it,
  not to anyone else in the workspace. While a phone approves for your account,
  a yes from the dashboard or from the agent's own client does not count. Either
  can still deny.
- **What the phone shows.** The workspace, the action, every target with the
  scope entry that allows it, the nodes, the options, the key that asked and
  where the request came from. Anything the agent wrote is marked as its own
  words, and every string is stripped of control and invisible characters before
  it is drawn. If the text does not match the digest the server sent with it, the
  phone offers only Deny.
- **Pushed when it arrives.** While the phone approves, the app gets a push
  token from Firebase Cloud Messaging and hands it to crossfyre.io with its own
  key. When a request or any other notification reaches your inbox,
  crossfyre.io pushes the phone through Google with the kind of notification,
  its id and a link made of ids, never its text. The app reads the notification
  from crossfyre.io and shows it: a request on the Approvals channel, which
  opens it in the app, and anything else on Alerts, which opens the Activity tab.
  The lock screen says that something arrived, not what. Turning Approvals off
  or signing out deletes the token. A phone without Google Play services, or a
  build without `firebase.properties`, gets no push; the app then asks
  crossfyre.io for waiting approvals every five seconds for two minutes while it
  is on screen, then every fifteen, and the alerts you set up in the dashboard
  still reach you. A link to `https://crossfyre.io/m/approve/<id>` opens the
  request in the app either way.
- **Stopping what you approved.** While a scan you approved is running, Recent
  decisions offers Stop. The stop is signed like an approval, after the same
  unlock and over the same request, with `stop` where an approval says
  `approve`, and at crossfyre.io's time: it takes a stop only within five
  minutes of its own clock. Your role in that workspace has to allow stopping
  scans.
- **The Activity tab** shows what is waiting, your recent decisions, your
  notifications, and the activity log as the dashboard shows it to you, under
  the same roles. crossfyre.io answers notifications and the log only for a
  phone that approves, never for the CLI's key on a computer, and the log
  cannot be exported from the phone. A notification's link opens only when it
  is a page on crossfyre.io: a request waiting for you opens in the app, and
  anything else in a browser tab. All of it is kept in memory while the app is
  open, and none of it is written to the phone's storage.

Signing out, turning Approvals off, or revoking the phone's key in the dashboard
stops the key from working. Removing the screen lock makes Android delete the
key, and the app says so.

The limit: an agent that drives your signed-in browser can do anything you can
do there, including confirming a phone it enrolled itself. Approvals protect
against agents that hold your keys outside the browser.

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
- Using the phone as a node for scans is planned and not built. The Node row
  on Home says so and does nothing.

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

# the approval key on an emulator, which the tests give a PIN and take it from
./gradlew :app:connectedDevDirectDebugAndroidTest
```

`build.sh` does the native step and a `devDirect` debug build in one go. The
gradle wrapper pins gradle 8.13 and verifies the distribution checksum.

Without a signing key the release builds are **unsigned**, which Android will
not install. That is deliberate: see `app/build.gradle.kts`.

Push needs `firebase.properties` at this directory's root, with the Firebase
project's `apiKey`, `projectId` and `senderId`, and each environment's app id as
`prod.appId`, `staging.appId` and `dev.appId`. These name the app to Firebase and
are not secrets. Without the file the app builds and runs with no push.

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
| `app/src/main` | the app both builds share: the `VpnService`, the Compose screens, sign-in, pairing and approvals |
| `app/src/prod`, `app/src/staging` | the link filters that open an approval from crossfyre.io or staging in the app |
| `app/src/direct` | the patch feature, in the direct build only |
| `app/src/play` | the Play build's stand-in for it, which says it is not available |
| `app/src/test*` | unit tests, shared and per build, with the approval fixtures the platform reads too |
| `app/src/androidTest` | tests of the approval key in the real keystore; they set and clear a PIN, so run them on an emulator |
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
