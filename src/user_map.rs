use std::collections::HashMap;

use crate::protocol::vless::UserId;

/// Measured crossover on the supported release build: a sorted, contiguous
/// lookup wins both hit and miss at 64 UUIDs; SipHash wins legitimate hits at
/// 128. Use the lower measured boundary rather than extrapolating between them.
const SORTED_USER_LIMIT: usize = 64;

/// An immutable UUID map whose representation follows measured cardinality.
///
/// Production configurations contain unique UUIDs. The defensive de-duplication
/// here preserves the former registry behavior for direct library callers.
#[derive(Clone, Debug)]
pub(crate) enum AdaptiveUserMap<V> {
    Sorted(Box<[(UserId, V)]>),
    Hashed(HashMap<UserId, V>),
}

impl<V> AdaptiveUserMap<V> {
    pub(crate) fn from_entries(entries: impl IntoIterator<Item = (UserId, V)>) -> Self {
        let mut entries: Vec<_> = entries.into_iter().collect();
        entries.sort_unstable_by_key(|(user_id, _)| *user_id);
        entries.dedup_by_key(|(user_id, _)| *user_id);
        if entries.len() <= SORTED_USER_LIMIT {
            Self::Sorted(entries.into_boxed_slice())
        } else {
            Self::Hashed(entries.into_iter().collect())
        }
    }

    pub(crate) fn get(&self, user_id: &UserId) -> Option<&V> {
        match self {
            Self::Sorted(entries) => entries
                .binary_search_by_key(user_id, |(candidate, _)| *candidate)
                .ok()
                .map(|index| &entries[index].1),
            Self::Hashed(entries) => entries.get(user_id),
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Sorted(entries) => entries.len(),
            Self::Hashed(entries) => entries.len(),
        }
    }
}

impl<V> Default for AdaptiveUserMap<V> {
    fn default() -> Self {
        Self::Sorted(Box::default())
    }
}

#[cfg(test)]
mod tests {
    use super::{AdaptiveUserMap, SORTED_USER_LIMIT};
    use crate::protocol::vless::UserId;

    #[test]
    fn selects_measured_representation_and_finds_entries() {
        let small = AdaptiveUserMap::from_entries(
            (0..SORTED_USER_LIMIT).map(|index| (user_id(index), index)),
        );
        assert!(matches!(small, AdaptiveUserMap::Sorted(_)));
        assert_eq!(small.get(&user_id(17)), Some(&17));

        let large = AdaptiveUserMap::from_entries(
            (0..=SORTED_USER_LIMIT).map(|index| (user_id(index), index)),
        );
        assert!(matches!(large, AdaptiveUserMap::Hashed(_)));
        assert_eq!(
            large.get(&user_id(SORTED_USER_LIMIT)),
            Some(&SORTED_USER_LIMIT)
        );
        assert_eq!(large.get(&user_id(SORTED_USER_LIMIT + 1)), None);
    }

    #[test]
    fn defensively_deduplicates_direct_callers() {
        let user = user_id(7);
        let map = AdaptiveUserMap::from_entries([(user, 1), (user, 2)]);
        assert_eq!(map.len(), 1);
    }

    fn user_id(index: usize) -> UserId {
        UserId::new((index as u128).to_be_bytes())
    }
}
