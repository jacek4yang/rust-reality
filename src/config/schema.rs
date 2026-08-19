use schemars::{Schema, schema_for};

use super::Config;

/// Builds the JSON Schema for the complete strict configuration model.
#[must_use]
pub fn config_schema() -> Schema {
    schema_for!(Config)
}

/// Serializes the configuration schema as pretty JSON.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn format_config_schema() -> Result<String, serde_json::Error> {
    let mut output = serde_json::to_string_pretty(&config_schema())?;
    output.push('\n');
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::format_config_schema;

    #[test]
    fn schema_excludes_removed_operational_surfaces() {
        let schema = format_config_schema().expect("schema must serialize");

        assert!(schema.contains("inbounds"));
        assert!(schema.contains("routing"));
        assert!(!schema.contains("metrics"));
        assert!(!schema.contains("\"health\""));
        assert!(!schema.contains("observability"));
        assert!(schema.contains("preSharedKey"));
        assert!(!schema.contains("minConnections"));
        assert!(!schema.contains("maxStreamsPerConnection"));
        assert!(!schema.contains("dedicatedAfterBytes"));
        assert!(schema.contains("\"dial\""));
        assert!(schema.contains("hardFailurePenaltySeconds"));
        assert!(schema.contains("latencyMemorySeconds"));
        assert!(schema.contains("dualStack"));
        assert!(!schema.contains("addressFamily"));
        assert!(!schema.contains("familyPenaltySeconds"));
        assert!(!schema.contains("healthMemorySeconds"));
        // v1.6 configuration model: profile, tuning, and the advanced escape
        // hatch are documented; the deprecated `policy` alias remains in the
        // schema because it is still accepted input.
        assert!(schema.contains("\"advanced\""));
        assert!(schema.contains("\"limits\""));
        assert!(schema.contains("\"profile\""));
        assert!(schema.contains("\"tuning\""));
        assert!(schema.contains("\"objective\""));
        assert!(schema.contains("\"policy\""));
        for value in [
            "auto",
            "shared",
            "fixed",
            "startup",
            "adaptive",
            "latency",
            "balanced",
            "throughput",
        ] {
            assert!(
                schema.contains(value),
                "missing tuning/profile value {value}"
            );
        }
        for policy in ["auto", "preferIpv4", "preferIpv6", "ipv4Only", "ipv6Only"] {
            assert!(schema.contains(policy), "missing dial mode {policy}");
        }
    }
}
