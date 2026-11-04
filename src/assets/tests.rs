use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    sync::Arc,
    thread,
    time::Duration,
};

use super::AssetFetcher;
use super::{
    AssetDownloadFailure, AssetLoadError, AssetMatcher, AssetSnapshot, AssetSource, AssetStore,
};
use crate::config::node::{entry::EntryConfig, fixture};

/// An entry node whose routing names geo conditions and whose assets come
/// from a local test server.
fn geo_entry(
    geosite_url: &str,
    directory: &std::path::Path,
    domain: &str,
    ip: &str,
) -> EntryConfig {
    let ip_rule = if ip.is_empty() {
        String::new()
    } else {
        format!(r#","ip":["{ip}"]"#)
    };
    let json = fixture::entry_without_routing(&format!(
        r#""listeners": [{{ "port": 443 }}],
  "assets": {{ "geoip": "{geosite_url}", "geosite": "{geosite_url}",
               "cacheDirectory": "{}" }},
  "routing": {{ "default": "direct",
    "rules": [{{ "name": "geo", "domain": ["{domain}"]{ip_rule}, "outbound": "block" }}] }}"#,
        directory.display()
    ));
    fixture::parsed(&json)
        .as_entry()
        .expect("the fixture is an entry node")
        .clone()
}

#[test]
fn loads_xray_geosite_and_geoip_wire_shapes() {
    let (config, directory) = fixture();
    let snapshot = AssetSnapshot::load(&config).expect("asset vectors must load");

    assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "api.example.com"));
    assert!(!snapshot.matches_domain(&AssetSource::GeoSite, "test", "notexample.com"));
    assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "has-NEEDLE-here.test"));
    assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "secure42.example"));
    assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "EXACT.example"));
    assert!(snapshot.matches_ip(
        &AssetSource::GeoIp,
        "private",
        Ipv4Addr::new(10, 1, 2, 3).into()
    ));
    assert!(!snapshot.matches_ip(
        &AssetSource::GeoIp,
        "private",
        Ipv4Addr::new(11, 1, 2, 3).into()
    ));
    assert!(snapshot.matches_ip(&AssetSource::GeoIp, "private", Ipv6Addr::LOCALHOST.into()));

    fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
}

#[test]
fn failed_reload_preserves_last_good_snapshot() {
    let (config, directory) = fixture();
    let store = AssetStore::new(&config).expect("initial assets must load");
    let before = store.load();
    fs::remove_file(directory.join("geoip.dat")).expect("temporary geoip must be removed");

    store
        .reload(&config)
        .expect_err("missing asset must fail reload");
    let after = store.load();

    assert!(Arc::ptr_eq(&before, &after));
    assert_eq!(after.generation(), 0);
    fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
}

#[test]
fn downloads_once_then_revalidates_cached_asset_with_etag() {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("asset test listener must bind");
    let address = listener.local_addr().expect("listener address must exist");
    let body = geosite_list();
    let server = thread::spawn(move || {
        for request_index in 0..2 {
            let (mut stream, _) = listener.accept().expect("asset request must arrive");
            let mut request = [0_u8; 4096];
            let length = stream.read(&mut request).expect("asset request must read");
            let request = String::from_utf8_lossy(&request[..length]);
            if request_index == 0 {
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"test-vector\"\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(headers.as_bytes())
                    .and_then(|()| stream.write_all(&body))
                    .expect("asset response must write");
            } else {
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("if-none-match: \"test-vector\"")
                );
                stream
                    .write_all(b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n")
                    .expect("asset response must write");
            }
        }
    });

    let suffix = format!("{}-etag", std::process::id());
    let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
    let config = geo_entry(
        &format!("http://{address}/geosite.dat"),
        &directory,
        "geosite:test",
        "",
    );

    let first = AssetSnapshot::load(&config).expect("downloaded asset must load");
    let second = AssetSnapshot::load(&config).expect("revalidated cache must load");

    assert!(first.matches_domain(&AssetSource::GeoSite, "test", "api.example.com"));
    assert!(second.matches_domain(&AssetSource::GeoSite, "test", "api.example.com"));
    server.join().expect("asset test server must complete");
    fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
}

#[test]
fn response_body_timeout_falls_back_to_validated_cache() {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("asset test listener must bind");
    let address = listener.local_addr().expect("listener address must exist");
    let body = geosite_list();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("asset request must arrive");
        let mut request = [0_u8; 4096];
        let length = stream.read(&mut request).expect("asset request must read");
        assert!(length > 0, "asset request must not be empty");
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .and_then(|()| stream.write_all(&body[..1]))
            .expect("partial asset response must write");
        thread::sleep(Duration::from_millis(1_500));
    });

    let suffix = format!("{}-body-timeout", std::process::id());
    let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
    fs::create_dir(&directory).expect("temporary asset cache must be created");
    fs::write(directory.join("geosite.dat"), geosite_list())
        .expect("cached geosite must be written");
    let config = geo_entry(
        &format!("http://{address}/geosite.dat"),
        &directory,
        "geosite:test",
        "",
    );

    let snapshot = AssetSnapshot::load(&config)
        .expect("a timed-out response body must fall back to the validated cache");

    assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "api.example.com"));
    server.join().expect("asset test server must complete");
    fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
}

#[test]
fn oversized_response_body_does_not_fall_back_to_validated_cache() {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("asset test listener must bind");
    let address = listener.local_addr().expect("listener address must exist");
    let maximum = 1024_usize;
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("asset request must arrive");
        let mut request = [0_u8; 4096];
        let length = stream.read(&mut request).expect("asset request must read");
        assert!(length > 0, "asset request must not be empty");
        let body = vec![0_u8; maximum + 2];
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .expect("oversized asset response must write");
    });

    let suffix = format!("{}-body-too-large", std::process::id());
    let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
    fs::create_dir(&directory).expect("temporary asset cache must be created");
    fs::write(directory.join("geosite.dat"), geosite_list())
        .expect("cached geosite must be written");
    let config = geo_entry(
        &format!("http://{address}/geosite.dat"),
        &directory,
        "geosite:test",
        "",
    );
    let fetcher = AssetFetcher::new(&config);

    let error = match fetcher.fetch(
        "geosite.dat",
        &format!("http://{address}/geosite.dat"),
        maximum,
    ) {
        Ok(_) => panic!("an oversized body must fail instead of using cached assets"),
        Err(error) => error,
    };
    match error {
        AssetLoadError::TooLarge {
            path,
            maximum: observed,
        } => {
            assert_eq!(path, directory.join("geosite.dat"));
            assert_eq!(observed, maximum);
        }
        other => panic!("oversized body returned the wrong error: {other}"),
    }

    server.join().expect("asset test server must complete");
    fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
}

#[test]
fn maximum_plus_one_response_body_does_not_fall_back_to_validated_cache() {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("asset test listener must bind");
    let address = listener.local_addr().expect("listener address must exist");
    let maximum = 1024_usize;
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("asset request must arrive");
        let mut request = [0_u8; 4096];
        let length = stream.read(&mut request).expect("asset request must read");
        assert!(length > 0, "asset request must not be empty");
        let body = vec![0_u8; maximum + 1];
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .expect("maximum-plus-one asset response must write");
    });

    let suffix = format!("{}-body-maximum-plus-one", std::process::id());
    let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
    fs::create_dir(&directory).expect("temporary asset cache must be created");
    fs::write(directory.join("geosite.dat"), geosite_list())
        .expect("cached geosite must be written");
    let config = geo_entry(
        &format!("http://{address}/geosite.dat"),
        &directory,
        "geosite:test",
        "",
    );
    let fetcher = AssetFetcher::new(&config);

    let error = match fetcher.fetch(
        "geosite.dat",
        &format!("http://{address}/geosite.dat"),
        maximum,
    ) {
        Ok(_) => panic!("a maximum-plus-one body must fail instead of using cached assets"),
        Err(error) => error,
    };
    match error {
        AssetLoadError::TooLarge {
            path,
            maximum: observed,
        } => {
            assert_eq!(path, directory.join("geosite.dat"));
            assert_eq!(observed, maximum);
        }
        other => panic!("maximum-plus-one body returned the wrong error: {other}"),
    }

    server.join().expect("asset test server must complete");
    fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
}

#[test]
fn http_error_falls_back_to_validated_cache() {
    let (address, server) = one_response_server("503 Service Unavailable");
    let (config, directory) = remote_geosite_fixture(address, "status-cache");
    fs::write(directory.join("geosite.dat"), geosite_list())
        .expect("cached geosite must be written");

    let snapshot =
        AssetSnapshot::load(&config).expect("an HTTP error must fall back to the validated cache");
    assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "api.example.com"));

    server.join().expect("asset test server must complete");
    fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
}

#[test]
fn http_error_with_missing_cache_preserves_download_failure() {
    let (address, server) = one_response_server("503 Service Unavailable");
    let (config, directory) = remote_geosite_fixture(address, "status-missing-cache");

    let error = match AssetSnapshot::load(&config) {
        Ok(_) => panic!("an HTTP error without cache must fail"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        AssetLoadError::Download(AssetDownloadFailure::HttpStatus(503))
    ));

    server.join().expect("asset test server must complete");
    fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
}

#[test]
#[ignore = "downloads the current community release from GitHub"]
fn loads_live_community_geoip_and_geosite_release() {
    let suffix = format!("{}-live", std::process::id());
    let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
    let config = geo_entry(
        crate::config::node::assets::DEFAULT_GEOSITE_URL,
        &directory,
        "geosite:cn",
        "geoip:private",
    );

    let snapshot = AssetSnapshot::load(&config).expect("community assets must load");

    assert!(snapshot.matches_domain(&AssetSource::GeoSite, "cn", "www.baidu.com"));
    assert!(snapshot.matches_ip(
        &AssetSource::GeoIp,
        "private",
        Ipv4Addr::new(10, 1, 2, 3).into()
    ));
    assert_eq!(snapshot.summary().domain_labels, 1);
    assert_eq!(snapshot.summary().ip_labels, 1);
    assert!(
        fs::metadata(directory.join("geoip.dat"))
            .expect("validated GeoIP cache must exist")
            .len()
            > 1024
    );
    assert!(
        fs::metadata(directory.join("geosite.dat"))
            .expect("validated GeoSite cache must exist")
            .len()
            > 1024
    );
    fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
}

fn one_response_server(status: &str) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("asset test listener must bind");
    let address = listener.local_addr().expect("listener address must exist");
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("asset request must arrive");
        let mut request = [0_u8; 4096];
        let length = stream.read(&mut request).expect("asset request must read");
        assert!(length > 0, "asset request must not be empty");
        stream
            .write_all(response.as_bytes())
            .expect("asset response must write");
    });
    (address, server)
}

fn remote_geosite_fixture(address: SocketAddr, suffix: &str) -> (EntryConfig, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(format!(
        "rust-reality-assets-{}-{suffix}",
        std::process::id()
    ));
    fs::create_dir(&directory).expect("temporary asset cache must be created");
    let config = geo_entry(
        &format!("http://{address}/geosite.dat"),
        &directory,
        "geosite:test",
        "",
    );
    (config, directory)
}

fn fixture() -> (EntryConfig, std::path::PathBuf) {
    let suffix = format!("{}-{:?}", std::process::id(), std::thread::current().id());
    let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
    fs::create_dir(&directory).expect("temporary asset cache must be created");
    fs::write(directory.join("geoip.dat"), geoip_list()).expect("temporary geoip must be written");
    fs::write(directory.join("geosite.dat"), geosite_list())
        .expect("temporary geosite must be written");
    // Port zero cannot host the source. Fail locally without depending on
    // external DNS latency, then exercise the validated cache fallback.
    let config = geo_entry(
        "http://127.0.0.1:0/geosite.dat",
        &directory,
        "geosite:test",
        "geoip:private",
    );
    (config, directory)
}

fn geosite_list() -> Vec<u8> {
    let mut site = Vec::new();
    bytes_field(&mut site, 1, b"TEST");
    for (kind, value) in [
        (2, "example.com"),
        (0, "needle"),
        (1, r"^secure[0-9]+\.example$"),
        (3, "exact.example"),
    ] {
        let mut domain = Vec::new();
        varint_field(&mut domain, 1, kind);
        bytes_field(&mut domain, 2, value.as_bytes());
        bytes_field(&mut site, 2, &domain);
    }
    let mut list = Vec::new();
    bytes_field(&mut list, 1, &site);
    list
}

fn geoip_list() -> Vec<u8> {
    let mut cidr = Vec::new();
    bytes_field(&mut cidr, 1, &[10, 0, 0, 0]);
    varint_field(&mut cidr, 2, 8);
    let mut ipv6 = Vec::new();
    bytes_field(&mut ipv6, 1, &Ipv6Addr::LOCALHOST.octets());
    varint_field(&mut ipv6, 2, 128);
    let mut entry = Vec::new();
    bytes_field(&mut entry, 1, b"PRIVATE");
    bytes_field(&mut entry, 2, &cidr);
    bytes_field(&mut entry, 2, &ipv6);
    let mut list = Vec::new();
    bytes_field(&mut list, 1, &entry);
    list
}

fn bytes_field(output: &mut Vec<u8>, number: u8, value: &[u8]) {
    output.push((number << 3) | 2);
    encode_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn varint_field(output: &mut Vec<u8>, number: u8, value: u64) {
    output.push(number << 3);
    encode_varint(output, value);
}

fn encode_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}
