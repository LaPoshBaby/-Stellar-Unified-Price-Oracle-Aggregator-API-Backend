// Issue #297 — contract-side utility namespace.
//
// The implementations live in crate::utils (Issue #298) so the proxy contract
// and the price-oracle contract share exactly one copy; this module keeps the
// `utils` seam called out by the contract-split issue and gives the contract
// submodules a single import point.

pub(crate) use crate::utils::{
    append_history, apply_reputation_decay, calculate_usd_price, deviation_exceeds,
    update_reputation, vec_contains_address,
};
