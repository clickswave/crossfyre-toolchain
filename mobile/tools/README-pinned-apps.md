# Capturing certificate-pinned apps

Crossfyre Mobile intercepts TLS using a CA it generates on the device. That
works for any app that *trusts* that CA. Two Android realities get in the way
of "just capture app X":

1. **User CAs are ignored.** Since Android 7, apps do not trust user-installed
   CAs unless they opt in via a network security configuration. See
   [OWASP MASTG](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0286/).
2. **Certificate pinning.** A pinned app demands a specific certificate and
   rejects even a trusted CA's leaf. Under interception it simply fails to
   connect, usually with a generic "something went wrong".

Neither can be fixed from outside the app on an unrooted phone.

## How the ecosystem solves this

The established answer is to modify the app so it accepts your certificate. The
public prior art is well documented:

- [`apk-mitm`](https://github.com/shroudedcode/apk-mitm) rewrites an APK's
  network security configuration and re-signs it.
- [`objection`](https://github.com/sensepost/objection) and
  [Frida](https://frida.re) hook pinning at runtime.
- [Magisk modules](https://github.com/NVISOsecurity/AlwaysTrustUserCerts) make
  the system trust user certificates outright.

Every one of these needs a workstation, and most need a rooted device or a
manual repackage per app. That is the state of the art described by
[OWASP MASTG](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0029/) and by
[NetSPI](https://www.netspi.com/blog/technical-blog/mobile-application-pentesting/four-ways-bypass-android-ssl-verification-certificate-pinning/).

## How Crossfyre Mobile does it

In the direct-download build, open the **Patch** tab, pick the app, and tap
**Patch this app**. The Google Play build does not include this feature. The
app is rewritten and re-signed so that it trusts this phone's certificate, and
you are handed installable packages back.
Android asks you to confirm removing the original and installing the patched
build. No workstation, no root.

The rewriting happens as a hosted service, which is why this part needs an
account and is not in this repository. Everything on the device side is here.

After patching, scope capture to the target (**Scope > Only these**) and start
capturing.

The app keeps its CA across restarts, so a patched app keeps working. **Reset
certificate** makes a new one, which invalidates every patch made with the old
one, so the app says how many patched apps a reset will break before doing it,
and marks each of them "Patch again" afterwards.

## What still will not work

Being straight about the limits, because you will hit them:

- **Tamper and Play Integrity detection.** Many finance and dating apps verify
  their own signature or call the Play Integrity API. Any re-signed build has a
  different signature, so the app may refuse to log in or fetch data even once
  pinning is out of the way. Symptoms: it opens but reports it cannot verify
  itself, forces a logout, or its API calls fail while the app shows the
  flows. Nothing that works without root beats this, ours included.
- **You have to re-login.** Replacing an installed app means removing the
  original first, so its data goes with it.
- **Not every app patches cleanly.** Some fail to rebuild. When that happens the
  app tells you rather than installing something broken. Each app's details
  screen says beforehand when it looks shielded.

For pinned apps that do not tamper-check, which is a large share of them, this
path works.

## Keeping your other apps working

While testing one target, put your everyday apps in **Scope > All except**
so they bypass capture entirely and keep working normally.

## Authorisation

Patch and intercept only apps you own or are explicitly authorised to test: your
own builds, or a target covered by a bug bounty or pentest scope. Modifying and
redistributing someone else's application outside that is not something this
tool licenses you to do.
