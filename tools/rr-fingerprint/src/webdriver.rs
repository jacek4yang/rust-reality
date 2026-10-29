//! Small W3C WebDriver client for genuine, fresh-profile browser observations.
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub fn collect(browser: &str, binary: &Path, out: &Path) -> Result<()> {
    if !matches!(browser, "chrome" | "firefox") {
        return Err("unsupported capture browser".into());
    }
    fs::create_dir(out)?;
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(45)))
        .proxy(None)
        .build();
    let agent: ureq::Agent = config.into();
    let base = "http://127.0.0.1:4444";
    for sample in 0..20 {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let token = format!("{stamp:x}-{sample:02x}");
        let mut caps = json!({"browserName":browser,"acceptInsecureCerts":false,"proxy":{"proxyType":"direct"}});
        if browser == "chrome" {
            caps["goog:chromeOptions"] =
                json!({"binary":binary,"args":["--no-first-run","--no-default-browser-check"]});
        } else {
            caps["moz:firefoxOptions"] =
                json!({"binary":binary,"prefs":{"security.enterprise_roots.enabled":true}});
        }
        let response: Value = agent
            .post(format!("{base}/session"))
            .send_json(json!({"capabilities":{"alwaysMatch":caps}}))?
            .body_mut()
            .read_json()?;
        let id = response["value"]["sessionId"]
            .as_str()
            .ok_or("missing WebDriver session ID")?;
        let result = (|| -> Result<()> {
            agent
                .post(format!("{base}/session/{id}/timeouts"))
                .send_json(json!({"pageLoad":30000,"script":10000,"implicit":0}))?;
            agent.post(format!("{base}/session/{id}/url")).send_json(
                json!({"url":format!("https://browser-capture.test:8443/sample-{token}")}),
            )?;
            let observed: Value = agent
                .post(format!("{base}/session/{id}/execute/sync"))
                .send_json(json!({"script":"return document.body.textContent;","args":[]}))?
                .body_mut()
                .read_json()?;
            if observed["value"].as_str() != Some(token.as_str()) {
                return Err("HTTPS response nonce mismatch".into());
            }
            fs::write(
                out.join(format!("sample-{sample:02}.json")),
                serde_json::to_vec_pretty(
                    &json!({"sample":token,"capabilitiesRequested":caps,"sessionCreated":response,"response":observed,"httpsVerified":true}),
                )?,
            )?;
            Ok(())
        })();
        // Always close the session, including after navigation/assertion failure.
        let cleanup = agent.delete(format!("{base}/session/{id}")).call();
        result?;
        cleanup?;
    }
    Ok(())
}
