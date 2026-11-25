//! Shared setup for tests that run the built `fabric` binary.

mod fresh_home;

use std::process::Output;

use fresh_home::fabric_in_fresh_home;

/// Runs `fabric agent-gateway <args>` in a fresh home whose saved connection
/// points at `host`, with no `FABRIC_*` variable inherited and exactly the
/// variables in `environment` set.
pub fn fabric_with_saved_host(
    host: &str,
    args: &[&str],
    environment: &[(&str, &str)],
) -> Output {
    let config = format!("current = \"test\"\n\n[connections.test]\nhost = \"{host}\"\n");
    let args: Vec<&str> = ["agent-gateway"]
        .into_iter()
        .chain(args.iter().copied())
        .collect();
    fabric_in_fresh_home(&args, &[("config.toml", &config)], environment, "")
}
