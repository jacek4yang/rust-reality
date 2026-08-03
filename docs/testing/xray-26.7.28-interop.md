# Xray 26.7.28 interoperability record

## Scope

This record proves that an unmodified Xray client can establish the production
public protocol stack and relay real traffic through rust-reality:

```text
curl -> Xray SOCKS5 inbound -> VLESS + REALITY + xtls-rprx-vision
     -> rust-reality -> direct -> destination
```

It does not measure Internet capacity or claim that one sample is a throughput
comparison. NXR is not involved in this public-client test.

## Reproducible command

```shell
XRAY_BIN=/home/jacek/src/Xray-core/xray ./scripts/test-xray-interop.sh
```

The script builds a release binary, creates fresh ephemeral UUID, X25519 and
short-ID material, starts both processes on loopback, transfers a deterministic
1 MiB object through Xray, verifies its SHA-256 digest, and optionally requests
one real HTTPS URL. All generated configuration and keys remain in a bounded
temporary directory that is removed on exit.

## Recorded environment

- Date: 2026-08-03 (Asia/Shanghai)
- rust-reality commit: `fac7175d8f213adc85fef6543bf9509056b037b3`
- Xray: `26.7.28`, commit `5ca6f4b`, Go `1.26.0`, Linux/amd64
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Kernel: Linux `6.12.94+deb13-amd64`, x86_64
- CPU: Intel Core i3-8100, 4 physical cores, 1 thread per core
- REALITY cover: `www.microsoft.com:443`, SNI `www.microsoft.com`
- Xray uTLS fingerprint: `chrome`

## Result

- Cover compatibility probe: compatible, TLS 1.3,
  `TLS_AES_256_GCM_SHA384`, X25519
- Local payload: 1,048,576 bytes
- Local SHA-256:
  `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83`
- Real HTTPS request: `https://www.bing.com/`, HTTP 302
- Real HTTPS sample: connect `0.000092 s`, first byte `0.691823 s`, total
  `0.692049 s`

Xray debug output recorded successful Vision padding/unpadding and authenticated
Direct-boundary detection for both the local HTTP transfer and the real TLS
request. The rust-reality log contained no rejection event.

## Interpretation

The result is a compatibility gate: Xray 26.7.28 successfully exercised the
actual VLESS + REALITY + Vision public entry, including application data and
half-close-sensitive relay behavior. Performance conclusions require repeated,
randomized same-host comparisons and are tracked separately.
