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
        assert!(!schema.contains("health"));
        assert!(!schema.contains("observability"));
    }
}
