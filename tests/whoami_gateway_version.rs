//! Runs the built `fabric` binary's `whoami` against a gateway that refuses
//! connections and checks that the version warning stays off standard output.

mod common;

use common::fabric_with_saved_host;

const TOKEN: &str = "agpat_test-token";
const VERSION_WARNING: &str = "warning: could not read the gateway version";

/// A loopback address with nothing listening, so every connection is refused.
fn refusing_host() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener
        .local_addr()
        .expect("local addr");
    drop(listener);
    format!("http://{address}")
}

#[test]
fn whoami_json_keeps_the_version_warning_on_stderr() {
    let host = refusing_host();

    let output = fabric_with_saved_host(&host, &["--output", "json", "whoami"], &[("FABRIC_TOKEN", TOKEN)]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let info: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON");
    assert_eq!(info["gateway_version"], serde_json::Value::Null, "{stdout}");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 1, "{stderr}");
    assert!(lines[0].starts_with(VERSION_WARNING), "{stderr}");
    assert!(!stdout.contains(VERSION_WARNING), "{stdout}");
    assert!(!stderr.contains(TOKEN), "{stderr}");
}
