#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::{
    http_proxy::{decode_basic_credentials, decode_http_proxy_request},
    nxr::{NxrKey, decode_authenticated_request, request_len_from_header},
    reality::ClientHello,
    socks5::{
        MAX_CONNECT_REQUEST_LEN, decode_connect_request, decode_method_request,
        encode_connect_request,
    },
    socks5_auth::{
        AuthenticationPolicy, MAX_CONNECT_REPLY_LEN, MethodSelection, decode_method_offer,
        decode_username_password_request, encode_connect_reply, encode_method_selection,
        select_method,
    },
    vless::{
        Address, Command, decode_request, decode_response, encode_vision_tcp_request,
        fuzz_decode_request_ref,
    },
};
use std::net::Ipv4Addr;

fuzz_target!(|input: &[u8]| {
    if let Ok(decoded) = decode_request(input) {
        if decoded.header().command() == Command::Tcp {
            if let Some(destination) = decoded.header().destination() {
                let mut output = [0_u8; 533];
                if let Ok(n) =
                    encode_vision_tcp_request(decoded.header().user_id(), destination, &mut output)
                {
                    let round_trip = decode_request(&output[..n]).expect("encoded request");
                    assert_eq!(round_trip.header().destination(), Some(destination));
                    assert_eq!(round_trip.header().user_id(), decoded.header().user_id());
                    assert!(round_trip.payload().is_empty());
                }
            }
        }
    }
    if let Ok(decoded) = decode_response(input) {
        let header_len = 2 + usize::from(input[1]);
        assert_eq!(decoded.payload(), &input[header_len..]);
    }
    fuzz_decode_request_ref(input);
    if let Ok(decoded) = decode_method_request(input) {
        assert!(decoded.consumed() <= input.len());
        assert_eq!(decoded.trailing(), &input[decoded.consumed()..]);
    }
    if let Ok(offer) = decode_method_offer(input) {
        assert!(offer.consumed() <= input.len());
        assert_eq!(offer.trailing(), &input[offer.consumed()..]);
        for policy in [
            AuthenticationPolicy::NoAuthentication,
            AuthenticationPolicy::UsernamePasswordRequired,
        ] {
            let selection = select_method(&offer, policy);
            assert!(matches!(
                selection,
                MethodSelection::NoAuthentication
                    | MethodSelection::UsernamePassword
                    | MethodSelection::NoAcceptableMethods
            ));
            let mut response = [0xa5; 2];
            assert_eq!(encode_method_selection(selection, &mut response), Ok(2));
        }
    }
    if let Ok(credentials) = decode_username_password_request(input) {
        assert!(credentials.consumed() <= input.len());
        assert_eq!(credentials.trailing(), &input[credentials.consumed()..]);
        assert!(!credentials.username().is_empty());
        assert!(!credentials.password().is_empty());
    }
    if let Ok(request) = decode_http_proxy_request(input) {
        assert!(request.consumed() <= input.len());
        for header in request.forward_headers() {
            assert!(!header.name().eq_ignore_ascii_case("proxy-authorization"));
            assert!(!header.name().eq_ignore_ascii_case("proxy-authenticate"));
            assert!(!header.name().eq_ignore_ascii_case("connection"));
        }
        if let Some(value) = request.proxy_authorization() {
            let _ = decode_basic_credentials(value);
        }
    }
    let _ = decode_basic_credentials(input);
    if let Ok(decoded) = decode_connect_request(input) {
        assert!(decoded.consumed() <= input.len());
        assert_eq!(decoded.payload(), &input[decoded.consumed()..]);

        let mut encoded = [0_u8; MAX_CONNECT_REQUEST_LEN];
        if let Ok(written) = encode_connect_request(decoded.destination(), &mut encoded) {
            let round_trip = decode_connect_request(&encoded[..written]).expect("encoded CONNECT");
            assert_eq!(round_trip.destination(), decoded.destination());
            assert_eq!(round_trip.consumed(), written);
            assert!(round_trip.payload().is_empty());
        }
    }
    if let Some(&status) = input.first() {
        let code = match status % 9 {
            0 => rust_reality::protocol::socks5_auth::ConnectReplyCode::Succeeded,
            1 => rust_reality::protocol::socks5_auth::ConnectReplyCode::GeneralFailure,
            2 => rust_reality::protocol::socks5_auth::ConnectReplyCode::ConnectionNotAllowed,
            3 => rust_reality::protocol::socks5_auth::ConnectReplyCode::NetworkUnreachable,
            4 => rust_reality::protocol::socks5_auth::ConnectReplyCode::HostUnreachable,
            5 => rust_reality::protocol::socks5_auth::ConnectReplyCode::ConnectionRefused,
            6 => rust_reality::protocol::socks5_auth::ConnectReplyCode::TtlExpired,
            7 => rust_reality::protocol::socks5_auth::ConnectReplyCode::CommandNotSupported,
            _ => rust_reality::protocol::socks5_auth::ConnectReplyCode::AddressTypeNotSupported,
        };
        let address = Address::Ipv4(Ipv4Addr::new(
            input.get(1).copied().unwrap_or_default(),
            input.get(2).copied().unwrap_or_default(),
            input.get(3).copied().unwrap_or_default(),
            input.get(4).copied().unwrap_or_default(),
        ));
        let mut response = [0xa5; MAX_CONNECT_REPLY_LEN];
        let _ = encode_connect_reply(code, &address, 0, &mut response);
    }
    if let Ok(hello) = ClientHello::parse_message(input) {
        let _ = hello.normalized_profile_class();
    }
    let _ = ClientHello::parse_record(input);
    let _ = request_len_from_header(input);
    let key = NxrKey::new([0x33; 32]);
    let _ = decode_authenticated_request(input, &key, 1_785_761_600, 30);
});
