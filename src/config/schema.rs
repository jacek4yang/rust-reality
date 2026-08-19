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
        // hatch are documented; the removed v1.5 `policy` alias must not
        // appear. Assert the enums at their schema paths — a bare
        // `contains("auto")` would pass on any unrelated enum value anywhere
        // in the schema.
        assert!(schema.contains("\"advanced\""));
        assert!(schema.contains("\"limits\""));
        assert!(schema.contains("\"profile\""));
        assert!(schema.contains("\"tuning\""));
        assert!(schema.contains("\"objective\""));
        assert!(!schema.contains("\"policy\""));
        let value: serde_json::Value =
            serde_json::from_str(&schema).expect("schema must be valid JSON");
        // Schemars renders a documented unit enum as `oneOf` of `const`
        // strings; collect the consts at the definition's schema path.
        let consts = |definition: &str| -> Vec<String> {
            value["$defs"][definition]["oneOf"]
                .as_array()
                .unwrap_or_else(|| panic!("{definition} must be a oneOf definition"))
                .iter()
                .map(|variant| {
                    variant["const"]
                        .as_str()
                        .unwrap_or_else(|| panic!("{definition} variant must be a const"))
                        .to_owned()
                })
                .collect()
        };
        assert_eq!(
            consts("RuntimeProfile"),
            ["auto", "shared", "dedicated"],
            "the profile enum must list exactly the v1.6 profiles"
        );
        assert_eq!(
            consts("TuningMode"),
            ["fixed", "startup", "adaptive"],
            "the tuning mode enum must list exactly the v1.6 modes"
        );
        assert_eq!(
            consts("Objective"),
            ["latency", "balanced", "throughput"],
            "the objective enum must list exactly the v1.6 objectives"
        );
        assert_eq!(
            value["$defs"]["RuntimeConfig"]["properties"]["profile"]["$ref"],
            serde_json::json!("#/$defs/RuntimeProfile"),
            "runtime.profile must reference the profile enum definition"
        );
        for policy in ["auto", "preferIpv4", "preferIpv6", "ipv4Only", "ipv6Only"] {
            assert!(schema.contains(policy), "missing dial mode {policy}");
        }
    }
}
