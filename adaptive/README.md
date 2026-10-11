# adaptive

The pacing and retry layer the Crossfyre engines call. Given how recent probes went,
it decides how many to run at once, how long to wait between them, and whether a
failed probe is worth trying again.

## Open baseline

This crate is the open reference implementation. It defines the interface the engines
(`doorward`, `ambulo`, `voyage`, and the core) use, and ships a conservative baseline so the
open toolchain builds and runs on its own, with nothing missing.

The baseline is intentionally plain: safe, steady defaults, not fast. The tuned pacing
that keeps a scan quick without overrunning the target is a Crossfyre platform feature
and does not live in this repository. A public checkout builds and runs against this
baseline as-is.

If you change the public interface here, keep it stable so callers do not break.
