//! The deployment topologies the documentation teaches, as whole files.
//!
//! Every other configuration test asks whether one file is valid. These ask
//! whether a *deployment* is coherent, which is a different question and the
//! one operators actually get wrong. A LINE→LANDING topology is two files on
//! two machines that must agree about a port, a pre-shared key, and — for
//! Handoff — which half of an X25519 pair goes where. Nothing in `check` can
//! see that, because `check` reads one file.
//!
//! So these tests assert three things about each documented topology:
//!
//! 1. every file in it validates,
//! 2. every file is already canonical, so a documentation page can show it
//!    verbatim and `rust-reality format` is a no-op on it,
//! 3. the files agree on every value that spans them.
//!
//! Property 3 is the reason the scenarios are built from generated material
//! rather than pasted constants: the test places both halves of one real key
//! pair, so a template that wired them backwards could not pass.

use rust_reality::{
    config::{ValidatedConfig, canonical, load_bytes},
    crypto::{generate_short_id, generate_uuid, generate_x25519_key_pair},
};
use std::path::Path;

/// Loads a configuration the way every command does, failing with the
/// operator-facing diagnostic rather than a debug dump.
fn validated(name: &str, json: &str) -> ValidatedConfig {
    let path = Path::new(name);
    load_bytes(path, json.as_bytes()).unwrap_or_else(|error| panic!("{name} must load:\n{error}"))
}

/// Asserts a documented configuration is already in the canonical form.
///
/// A documentation page shows exactly this text, so if `format` would rewrite
/// it, the page is teaching a shape the project does not itself use.
fn assert_canonical(name: &str, json: &str) {
    let config = validated(name, json);
    let formatted = canonical(&config);
    assert_eq!(
        formatted, json,
        "{name} is not canonical; `rust-reality format` would rewrite it"
    );
}

/// One node's worth of generated material, held so a topology can place the
/// matching halves on both sides.
struct Material {
    user_id: String,
    short_id: String,
    entry_private_key: String,
    cover_public_key: String,
    landing_private_key: String,
    landing_public_key: String,
    psk: String,
}

impl Material {
    fn generate() -> Self {
        let entry = generate_x25519_key_pair().expect("entry key pair");
        let landing = generate_x25519_key_pair().expect("landing key pair");
        let psk = generate_x25519_key_pair().expect("pre-shared key");
        let (entry_private_key, cover_public_key) = entry.into_parts();
        let (landing_private_key, landing_public_key) = landing.into_parts();
        Self {
            user_id: generate_uuid().expect("user id").to_string(),
            short_id: generate_short_id(8).expect("short id"),
            entry_private_key: entry_private_key.expose().to_owned(),
            cover_public_key,
            landing_private_key: landing_private_key.expose().to_owned(),
            landing_public_key,
            // A pre-shared key is 32 random bytes in the same encoding, so an
            // X25519 secret is a perfectly good source of one here.
            psk: psk.into_parts().0.expose().to_owned(),
        }
    }
}

/// The smallest configuration that serves traffic: one node, direct egress.
fn standalone(material: &Material) -> String {
    format!(
        r#"{{
  "role": "entry",
  "listeners": [
    {{
      "port": 443
    }}
  ],
  "reality": {{
    "cover": "www.microsoft.com:443",
    "privateKey": "{private_key}"
  }},
  "users": [
    {{
      "id": "{user_id}",
      "shortIds": [
        "{short_id}"
      ],
      "label": "alice"
    }}
  ],
  "routing": {{
    "default": "direct"
  }}
}}
"#,
        private_key = material.entry_private_key,
        user_id = material.user_id,
        short_id = material.short_id,
    )
}

/// The public half of a LINE→LANDING deployment over NXR.
fn line_over_nxr(material: &Material, landing_port: u16) -> String {
    format!(
        r#"{{
  "role": "entry",
  "listeners": [
    {{
      "port": 443
    }}
  ],
  "reality": {{
    "cover": "www.microsoft.com:443",
    "privateKey": "{private_key}"
  }},
  "users": [
    {{
      "id": "{user_id}",
      "shortIds": [
        "{short_id}"
      ],
      "label": "alice"
    }}
  ],
  "outbounds": {{
    "landing-1": {{
      "type": "nxr",
      "address": "10.0.0.2",
      "port": {landing_port},
      "psk": "{psk}"
    }}
  }},
  "routing": {{
    "default": "landing-1",
    "rules": [
      {{
        "name": "block-private",
        "ip": [
          "10.0.0.0/8",
          "192.168.0.0/16"
        ],
        "outbound": "block"
      }}
    ]
  }}
}}
"#,
        private_key = material.entry_private_key,
        user_id = material.user_id,
        short_id = material.short_id,
        psk = material.psk,
    )
}

/// The hidden half of the same deployment.
fn nxr_landing(material: &Material, landing_port: u16) -> String {
    format!(
        r#"{{
  "role": "landing",
  "listeners": [
    {{
      "port": {landing_port},
      "ip": "ipv4Only",
      "ipv4": "10.0.0.2"
    }}
  ],
  "landing": {{
    "protocol": "nxr",
    "psk": "{psk}"
  }}
}}
"#,
        psk = material.psk,
    )
}

/// The public half of a Handoff deployment: the entry node holds the
/// landing's *public* key, never its private half.
fn line_over_handoff(material: &Material, landing_port: u16) -> String {
    format!(
        r#"{{
  "role": "entry",
  "listeners": [
    {{
      "port": 443
    }}
  ],
  "reality": {{
    "cover": "www.microsoft.com:443",
    "privateKey": "{private_key}"
  }},
  "users": [
    {{
      "id": "{user_id}",
      "shortIds": [
        "{short_id}"
      ],
      "label": "alice",
      "policy": "split"
    }}
  ],
  "outbounds": {{
    "landing-1": {{
      "type": "handoff",
      "address": "10.0.0.2",
      "port": {landing_port},
      "psk": "{psk}",
      "landingPublicKey": "{landing_public_key}"
    }}
  }},
  "routing": {{
    "default": "landing-1",
    "rules": [
      {{
        "name": "block-private",
        "ip": [
          "10.0.0.0/8"
        ],
        "outbound": "block"
      }}
    ],
    "policies": {{
      "split": {{
        "default": "landing-1",
        "rules": [
          {{
            "name": "home-direct",
            "domain": [
              "domain:example.com"
            ],
            "outbound": "direct"
          }}
        ]
      }}
    }}
  }}
}}
"#,
        private_key = material.entry_private_key,
        user_id = material.user_id,
        short_id = material.short_id,
        psk = material.psk,
        landing_public_key = material.landing_public_key,
    )
}

/// The hidden half of the Handoff deployment: it holds the private key whose
/// public half the entry node carries.
fn handoff_landing(material: &Material, landing_port: u16) -> String {
    format!(
        r#"{{
  "role": "landing",
  "listeners": [
    {{
      "port": {landing_port},
      "ip": "ipv4Only",
      "ipv4": "10.0.0.2"
    }}
  ],
  "landing": {{
    "protocol": "handoff",
    "psk": "{psk}",
    "privateKey": "{landing_private_key}"
  }}
}}
"#,
        psk = material.psk,
        landing_private_key = material.landing_private_key,
    )
}

#[test]
fn the_standalone_topology_is_valid_and_canonical() {
    let material = Material::generate();
    let config = standalone(&material);

    assert_canonical("standalone/config.json", &config);

    // The server file holds the private half. The public half is what the
    // operator copies into the client, and it must never appear here — a page
    // that showed both in one block would be teaching the wrong halves.
    assert!(config.contains(&material.entry_private_key));
    assert!(
        !config.contains(&material.cover_public_key),
        "the REALITY public key belongs in the client configuration, not the server's"
    );
}

#[test]
fn the_nxr_topology_is_valid_canonical_and_agrees_across_both_nodes() {
    let material = Material::generate();
    let port = 7443;
    let line = line_over_nxr(&material, port);
    let landing = nxr_landing(&material, port);

    assert_canonical("line/config.json", &line);
    assert_canonical("landing/config.json", &landing);

    // The three values that span the two machines. A deployment where any one
    // of them disagrees fails at the first transfer, not at `check`.
    assert!(
        line.contains(&format!("\"port\": {port}"))
            && landing.contains(&format!("\"port\": {port}")),
        "the entry must dial the port the landing binds"
    );
    assert_eq!(
        line.matches(&material.psk).count(),
        1,
        "the entry states the pre-shared key exactly once"
    );
    assert_eq!(
        landing.matches(&material.psk).count(),
        1,
        "the landing states the same pre-shared key"
    );
}

#[test]
fn the_handoff_topology_puts_each_half_of_the_key_pair_on_the_right_node() {
    let material = Material::generate();
    let port = 7443;
    let line = line_over_handoff(&material, port);
    let landing = handoff_landing(&material, port);

    assert_canonical("line/config.json", &line);
    assert_canonical("landing/config.json", &landing);

    assert!(
        line.contains(&material.landing_public_key),
        "the entry node carries the landing's public key"
    );
    assert!(
        !line.contains(&material.landing_private_key),
        "a private key must never appear in the file on the burnable public node"
    );
    assert!(
        landing.contains(&material.landing_private_key),
        "the landing holds the private half"
    );
    assert!(
        !landing.contains(&material.landing_public_key),
        "the landing derives its public half; restating it would be a second \
         representation of one value"
    );
}

/// Cross-node agreement is exactly what a single-file validator cannot see.
///
/// This is not a defect to fix by making `check` cleverer — `check` is given
/// one file and is offline by design. It is the reason the topology pages
/// must show both sides together, and the reason this test file exists.
#[test]
fn a_topology_whose_halves_disagree_still_validates_file_by_file() {
    let material = Material::generate();
    let stranger = Material::generate();

    // Wrong port on the entry side.
    validated("line/config.json", &line_over_nxr(&material, 7443));
    validated("landing/config.json", &nxr_landing(&material, 7444));

    // A pre-shared key from an unrelated deployment.
    validated("line/config.json", &line_over_nxr(&stranger, 7443));
    validated("landing/config.json", &nxr_landing(&material, 7443));

    // A landing public key that belongs to a different landing: the sealed
    // transfer would never open, and no amount of single-file validation can
    // say so.
    let mismatched = Material {
        landing_public_key: stranger.landing_public_key.clone(),
        ..Material::generate()
    };
    validated("line/config.json", &line_over_handoff(&mismatched, 7443));
}

/// A landing node has no routing, no users, and no REALITY identity.
///
/// The role discriminator is what makes this expressible: under a generic
/// inbound array, the fields a landing must not have would still parse.
#[test]
fn a_landing_rejects_every_field_that_belongs_to_an_entry() {
    let material = Material::generate();
    let base = handoff_landing(&material, 7443);

    for (field, fragment) in [
        (
            "reality",
            r#""reality": { "cover": "a:443", "privateKey": "x" }"#,
        ),
        ("users", r#""users": []"#),
        ("routing", r#""routing": { "default": "direct" }"#),
        ("assets", r#""assets": {}"#),
    ] {
        let json = base.replace(
            r#"  "landing": {"#,
            &format!("  {fragment},\n  \"landing\": {{"),
        );
        let error = load_bytes(Path::new("landing/config.json"), json.as_bytes())
            .expect_err("an entry-only field must not parse under the landing role");
        let rendered = error.to_string();
        assert!(
            rendered.contains(field),
            "the diagnostic must name `{field}`: {rendered}"
        );
    }
}

/// Two secrets in one file may not be the same value.
///
/// Reusing one generated key for two purposes is the shortcut an operator
/// reaches for when a page says "generate an X25519 key pair" twice. Inside
/// one file that is catchable, and it is caught.
#[test]
fn one_generated_value_may_not_serve_two_purposes_in_one_file() {
    let material = Material::generate();
    let json = line_over_handoff(&material, 7443).replace(
        &format!("\"psk\": \"{}\"", material.psk),
        &format!("\"psk\": \"{}\"", material.entry_private_key),
    );

    let error = load_bytes(Path::new("line/config.json"), json.as_bytes())
        .expect_err("one value used as both the REALITY key and a landing PSK must be refused");

    let rendered = error.to_string();
    assert!(
        rendered.contains("psk") || rendered.contains("privateKey"),
        "the diagnostic must name a field holding the reused value: {rendered}"
    );
    assert!(
        !rendered.contains(&material.entry_private_key),
        "a diagnostic must never echo the secret it is complaining about"
    );
}
