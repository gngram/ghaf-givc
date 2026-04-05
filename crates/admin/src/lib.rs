// SPDX-FileCopyrightText: 2025-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;

pub mod admin;
pub mod systemd_api;
pub mod utils;

pub mod pb {
    // Re-export to keep current code untouched
    pub use givc_common::pb::*;
}
pub use givc_client::endpoint;
pub use givc_common::types;

/// Init logging
///
/// # Errors
///
/// Will return `Err` if failed to initialize logging
pub fn trace_init() -> anyhow::Result<()> {
    use std::env;
    use tracing::Level;
    use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt};

    let env_filter =
        EnvFilter::try_from_env("GIVC_LOG").unwrap_or_else(|_| EnvFilter::from("info"));
    let is_debug_log_level = env_filter
        .max_level_hint()
        .map_or_else(|| false, |level| level >= Level::DEBUG);

    let output = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(is_debug_log_level)
        .with_file(is_debug_log_level)
        .with_line_number(is_debug_log_level)
        .with_thread_ids(is_debug_log_level);

    let output = if is_debug_log_level {
        output.pretty().boxed()
    } else {
        output.boxed()
    };

    if env::var("INVOCATION_ID").is_ok() {
        // systemd already captures stderr into journald, so keep a single sink here
        let journald = tracing_journald::layer()
            .map(|layer| layer.with_filter(env_filter.clone()).boxed())
            .unwrap_or(output.with_filter(env_filter).boxed());

        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(journald))
            .context("tracing shouldn't already have been set up")?;
    } else {
        tracing::subscriber::set_global_default(
            tracing_subscriber::registry().with(output.with_filter(env_filter)),
        )
        .context("tracing shouldn't already have been set up")?;
    }
    Ok(())
}
