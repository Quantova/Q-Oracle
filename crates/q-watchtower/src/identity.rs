// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WatchtowerId(pub u32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_watchtowers_have_distinct_ids() {
        assert_ne!(WatchtowerId(1), WatchtowerId(2));
    }

    #[test]
    fn the_same_id_compares_equal() {
        assert_eq!(WatchtowerId(7), WatchtowerId(7));
    }

    #[test]
    fn ids_order_the_same_way_the_wrapped_number_does() {
        assert!(WatchtowerId(1) < WatchtowerId(2));
    }
}
