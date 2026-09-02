//! Name-keyed sections that reject a repeated name.
//!
//! `outbounds` and `routing.policies` are objects whose keys are identities:
//! a rule saying `"outbound": "landing-1"` means whichever object carries that
//! key. serde's derived struct deserializer already rejects a repeated *field*
//! — `duplicate field \`routing\`` is an existing diagnostic — but a repeated
//! *map* key is not a field, and the default `BTreeMap` deserializer keeps the
//! last one silently.
//!
//! That would be a real failure: an operator who pastes a second `landing-1`
//! block loses the first one, and every rule that names it starts pointing
//! somewhere else with nothing reported. Making the name load-bearing means
//! rejecting the ambiguity.

use std::{collections::BTreeMap, fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};

/// Deserializes an optional name-keyed section, rejecting a repeated name.
///
/// Used with `#[serde(default, deserialize_with = "…")]`, so it runs only when
/// the section is present and an absent section stays `None`.
///
/// # Errors
///
/// Returns an error when the value is not an object, when an entry fails to
/// deserialize, or when a name appears more than once.
pub(crate) fn optional_unique_map<'de, D, V>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, V>>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    deserializer
        .deserialize_map(UniqueMapVisitor::<V>(PhantomData))
        .map(Some)
}

struct UniqueMapVisitor<V>(PhantomData<fn() -> V>);

impl<'de, V> Visitor<'de> for UniqueMapVisitor<V>
where
    V: Deserialize<'de>,
{
    type Value = BTreeMap<String, V>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object whose keys are unique names")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut entries = BTreeMap::new();
        while let Some(name) = access.next_key::<String>()? {
            let value = access.next_value()?;
            if entries.insert(name.clone(), value).is_some() {
                return Err(de::Error::custom(format!("duplicate name `{name}`")));
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    use super::optional_unique_map;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Holder {
        #[serde(default, deserialize_with = "optional_unique_map")]
        items: Option<BTreeMap<String, u32>>,
    }

    #[test]
    fn an_absent_section_stays_absent() {
        let holder: Holder = serde_json::from_str("{}").expect("holder must decode");

        assert_eq!(holder.items, None);
    }

    #[test]
    fn distinct_names_decode_in_sorted_order() {
        let holder: Holder =
            serde_json::from_str(r#"{"items":{"b":2,"a":1}}"#).expect("holder must decode");

        let items = holder.items.expect("items must be present");
        assert_eq!(items.len(), 2);
        assert_eq!(
            items.keys().map(String::as_str).collect::<Vec<_>>(),
            ["a", "b"],
            "a name-keyed section has no meaningful input order, so it is stored sorted"
        );
    }

    #[test]
    fn an_empty_section_is_accepted_and_stays_distinguishable_from_absent() {
        let holder: Holder = serde_json::from_str(r#"{"items":{}}"#).expect("holder must decode");

        assert_eq!(holder.items, Some(BTreeMap::new()));
    }

    #[test]
    fn a_repeated_name_is_rejected_by_name() {
        let error = serde_json::from_str::<Holder>(r#"{"items":{"a":1,"a":2}}"#)
            .expect_err("a repeated name must not decode");

        assert!(
            error.to_string().contains("duplicate name `a`"),
            "the error must name the ambiguous key: {error}"
        );
    }

    #[test]
    fn a_non_object_section_is_rejected() {
        assert!(serde_json::from_str::<Holder>(r#"{"items":[]}"#).is_err());
        assert!(serde_json::from_str::<Holder>(r#"{"items":"a"}"#).is_err());
    }
}
