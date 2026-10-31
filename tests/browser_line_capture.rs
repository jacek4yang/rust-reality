//! Capture the actual configured LINE handshake, before any destination opens.
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use rust_reality::{client::Line, config::node::LineConfig};
use tokio::{io::AsyncReadExt, net::TcpListener};

#[tokio::test(flavor = "current_thread")]
async fn per_line_profiles_emit_native_comparison_records() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    for profile in ["chrome", "firefox"] {
        let config: LineConfig = serde_json::from_value(serde_json::json!({
            "tag": profile, "address": "127.0.0.1", "port": port,
            "id": "11111111-1111-4111-8111-111111111111",
            "publicKey": BASE64_URL_SAFE_NO_PAD.encode([0x22; 32]),
            "shortId": "0102030405060708", "serverName": "browser-capture.test",
            "fingerprint": profile
        }))
        .unwrap();
        let line = Line::from_config(&config).unwrap();
        for sample in 0..32 {
            let capture = async {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut header = [0; 5];
                socket.read_exact(&mut header).await.unwrap();
                assert_eq!(&header[..3], &[22, 3, 1]);
                let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                assert!(length <= rust_reality::protocol::reality::MAX_CLIENT_HELLO_BYTES);
                let mut wire = header.to_vec();
                wire.resize(5 + length, 0);
                socket.read_exact(&mut wire[5..]).await.unwrap();
                // Close after capture. Authenticated completion is exercised by
                // the process E2E suite; this fixture endpoint has no server key.
                wire
            };
            let (wire, result) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(capture, line.handshake())
            })
            .await
            .unwrap();
            assert!(result.is_err());
            let hello = rust_reality::protocol::reality::ClientHello::parse_record(&wire).unwrap();
            assert_eq!(hello.key_share_group_offered(23), profile == "firefox");
            assert_eq!(hello.server_name(), Some("browser-capture.test"));
            if let Some(directory) = std::env::var_os("RR_BROWSER_COMPARISON_OUTPUT") {
                let directory = std::path::PathBuf::from(directory);
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(directory.join(format!("{profile}-{sample:02}.tls")), wire).unwrap();
            }
        }
    }
}
