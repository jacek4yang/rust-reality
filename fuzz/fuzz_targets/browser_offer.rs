#![no_main]
use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::reality::{
    AuthPlaintext, BrowserFingerprint, CLIENT_VERSION, ClientHello, ClientKeyAgreement,
    build_client_hello,
};
fuzz_target!(|input: &[u8]| {
    let profile = if input.first().is_some_and(|b| b & 1 != 0) {
        BrowserFingerprint::Firefox
    } else {
        BrowserFingerprint::Chrome
    };
    let name = String::from_utf8_lossy(&input[..input.len().min(300)]);
    let keys = ClientKeyAgreement::for_profile(profile).expect("OS entropy");
    let auth = AuthPlaintext {
        version: CLIENT_VERSION,
        time: 1,
        short_id: [1; 8],
    };
    if let Ok((hello, _)) =
        build_client_hello(&name, &[b"h2", b"http/1.1"], &keys, &[0x22; 32], auth)
    {
        let wire = hello.record();
        let parsed = ClientHello::parse_record(&wire).expect("serialized hello parses");
        assert_eq!(parsed.server_name(), Some(name.as_ref()));
        let _ = parsed.normalized_profile_class();
        let independent = rr_fingerprint::decode(&wire).expect("independent decoder");
        assert_eq!(independent.records.len(), 1);
    }
});
