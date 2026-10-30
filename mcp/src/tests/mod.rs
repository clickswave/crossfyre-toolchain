//! The rails: each one points a tool at something it must not do and counts, at a
//! socket or in the engine's own record, that it did not; then at something it must
//! do, so a server that does nothing cannot pass.

mod address_rail;
mod audit_rail;
mod cancel_rail;
mod confirm_rail;
mod engine_rail;
#[cfg(unix)]
pub(crate) mod fake_wb;
mod http_rail;
mod injection_rail;
mod jobs_paging;
mod limits_rail;
mod redirect_rail;
mod scope_rail;
pub(crate) mod support;
mod tools_snapshot;
mod workbench_rail;
