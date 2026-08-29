// Issue #68: Proxy contract with upgradeability via WASM hash replacement.
//
// Storage collision prevention: proxy-configuration keys (Implementation,
// PreviousImplementation, ContractVersion, StorageLayoutVersion) live under
// the same DataKey enum as oracle state but are clearly namespaced by their
// variants and stored in instance storage — the same contract always owns
// both sets.  If a new storage layout is introduced, bump
// StorageLayoutVersion via `set_storage_layout_version` before or after the
// WASM swap so migration code can detect the change.
//
// Issue #298 — the shared helpers (deviation_exceeds, update_reputation,
// calculate_usd_price, ...) are imported from crate::utils instead of being
// duplicated here, so proxy and oracle behavior can never drift apart.

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Vec};

use crate::errors::OracleError;
use crate::storage;
use crate::types::{AssetPrice, MultiSigConfig, PriceDataPoint, SourceReputation};
use crate::utils;

// Issue #375 — minimum delay between a queued WASM upgrade and its execution.
const UPGRADE_TIMELOCK_SECS: u64 = 172_800; // 48 hours

#[contract]
pub struct ProxyContract;

#[contractimpl]
impl ProxyContract {
    // -------------------------------------------------------------------------
    // Issue #68 — initialize proxy
    // -------------------------------------------------------------------------

    pub fn initialize(env: Env, admin: Address, implementation: Address) {
        storage::set_admin(&env, &admin);
        storage::set_implementation(&env, &implementation);
        storage::set_contract_version(&env, 1);
        storage::set_storage_layout_version(&env, 1);
    }

    // -------------------------------------------------------------------------
    // Issue #375 — multi-sig configuration for the upgrade quorum.
    // -------------------------------------------------------------------------

    pub fn init_multisig(
        env: Env,
        admin: Address,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        if threshold == 0 || threshold as usize > signers.len() as usize {
            return Err(OracleError::InvalidThreshold);
        }
        storage::set_multisig_config(&env, &MultiSigConfig { signers, threshold });
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Issue #375 — WASM-level upgrade, gated by multi-sig quorum + timelock.
    //
    // Lifecycle: propose_upgrade → approve_upgrade (×N until quorum) →
    // execute_upgrade (only once the timelock ETA has passed). Requires a
    // multi-sig config to already be set via the oracle's `init_multisig`.
    // -------------------------------------------------------------------------

    pub fn propose_upgrade(
        env: Env,
        admin: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<u64, OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::get_multisig_config(&env).ok_or(OracleError::MultiSigNotInitialized)?;

        let eta = env.ledger().timestamp() + UPGRADE_TIMELOCK_SECS;
        storage::set_pending_upgrade(&env, &new_wasm_hash, eta);

        env.events()
            .publish(("upgrade_proposed", admin), (new_wasm_hash, eta));
        Ok(eta)
    }

    pub fn approve_upgrade(env: Env, signer: Address) -> Result<u32, OracleError> {
        signer.require_auth();

        let config = storage::get_multisig_config(&env).ok_or(OracleError::MultiSigNotInitialized)?;
        if !utils::vec_contains_address(&config.signers, &signer) {
            return Err(OracleError::NotASigner);
        }
        storage::get_pending_upgrade(&env).ok_or(OracleError::UpgradeNotProposed)?;

        let approvals = storage::get_upgrade_approvals(&env);
        if utils::vec_contains_address(&approvals, &signer) {
            return Err(OracleError::UpgradeAlreadyApproved);
        }

        storage::record_upgrade_approval(&env, &signer);
        let count = storage::get_upgrade_approvals(&env).len();

        env.events().publish(("upgrade_approved", signer), count);
        Ok(count)
    }

    pub fn execute_upgrade(env: Env, caller: Address) -> Result<(), OracleError> {
        caller.require_auth();

        let new_wasm_hash =
            storage::get_pending_upgrade(&env).ok_or(OracleError::UpgradeNotProposed)?;
        let eta = storage::get_pending_upgrade_eta(&env).unwrap_or(u64::MAX);
        if env.ledger().timestamp() < eta {
            return Err(OracleError::UpgradeTimelockNotElapsed);
        }

        let config = storage::get_multisig_config(&env).ok_or(OracleError::MultiSigNotInitialized)?;
        let approvals = storage::get_upgrade_approvals(&env);
        if approvals.len() < config.threshold {
            return Err(OracleError::ThresholdNotMet);
        }

        let current_version = storage::get_contract_version(&env);
        storage::set_contract_version(&env, current_version + 1);
        storage::clear_pending_upgrade(&env);

        env.events()
            .publish(("upgrade_executed", new_wasm_hash.clone()), current_version + 1);

        env.deployer().update_current_contract_wasm(new_wasm_hash);
        Ok(())
    }

    pub fn cancel_upgrade(env: Env, admin: Address) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::clear_pending_upgrade(&env);
        env.events()
            .publish(("upgrade_cancelled", admin), env.ledger().timestamp());
        Ok(())
    }

    pub fn get_pending_upgrade(env: Env) -> Option<BytesN<32>> {
        storage::get_pending_upgrade(&env)
    }

    pub fn get_pending_upgrade_eta(env: Env) -> Option<u64> {
        storage::get_pending_upgrade_eta(&env)
    }

    pub fn get_upgrade_approval_count(env: Env) -> u32 {
        storage::get_upgrade_approvals(&env).len()
    }

    // -------------------------------------------------------------------------
    // Issue #375 — canary rollout
    //
    // A canary implementation is registered ahead of a canonical upgrade so
    // off-chain routers (the aggregator/API layer) can steer a configured
    // traffic share to it before `promote_canary` makes it canonical. This
    // contract only tracks the registration; traffic routing itself happens
    // off-chain, since Soroban contracts cannot randomly split inbound calls.
    // -------------------------------------------------------------------------

    pub fn set_canary(
        env: Env,
        admin: Address,
        canary: Address,
        traffic_share_bps: u32,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        if traffic_share_bps > 10_000 {
            return Err(OracleError::InvalidThreshold);
        }
        storage::set_canary(&env, &canary, traffic_share_bps);
        env.events().publish(("canary_set", canary), traffic_share_bps);
        Ok(())
    }

    pub fn get_canary(env: Env) -> Option<(Address, u32)> {
        storage::get_canary(&env)
    }

    pub fn promote_canary(env: Env, admin: Address) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;

        let (canary, _) = storage::get_canary(&env).ok_or(OracleError::UpgradeNotProposed)?;

        if let Some(old) = storage::get_implementation(&env) {
            storage::set_previous_implementation(&env, &old);
        }
        storage::set_implementation(&env, &canary);

        let current_version = storage::get_contract_version(&env);
        storage::set_contract_version(&env, current_version + 1);
        storage::clear_canary(&env);

        env.events()
            .publish(("canary_promoted", canary), current_version + 1);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Issue #68 — logical implementation pointer upgrade
    // Tracks which implementation address the proxy delegates intent to.
    // -------------------------------------------------------------------------

    pub fn upgrade(
        env: Env,
        admin: Address,
        new_implementation: Address,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;

        if let Some(old) = storage::get_implementation(&env) {
            storage::set_previous_implementation(&env, &old);
        }

        storage::set_implementation(&env, &new_implementation);

        let current_version = storage::get_contract_version(&env);
        storage::set_contract_version(&env, current_version + 1);

        env.events()
            .publish(("implementation_updated", admin), (new_implementation, current_version + 1));

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Issue #68 — storage layout migration support
    // -------------------------------------------------------------------------

    pub fn get_storage_layout_version(env: Env) -> u32 {
        storage::get_storage_layout_version(&env)
    }

    pub fn set_storage_layout_version(
        env: Env,
        admin: Address,
        version: u32,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::set_storage_layout_version(&env, version);
        Ok(())
    }

    pub fn get_implementation(env: Env) -> Option<Address> {
        storage::get_implementation(&env)
    }

    pub fn get_previous_implementation(env: Env) -> Option<Address> {
        storage::get_previous_implementation(&env)
    }

    pub fn get_version(env: Env) -> u32 {
        storage::get_contract_version(&env)
    }

    pub fn set_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), OracleError> {
        current_admin.require_auth();
        storage::verify_admin(&env, &current_admin)?;
        storage::set_admin(&env, &new_admin);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Issue #69 — deviation threshold (delegated through proxy)
    // -------------------------------------------------------------------------

    pub fn set_deviation_threshold(
        env: Env,
        admin: Address,
        threshold_bps: u32,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::set_deviation_threshold(&env, threshold_bps);
        Ok(())
    }

    pub fn get_deviation_threshold(env: Env) -> Option<u32> {
        storage::get_deviation_threshold(&env)
    }

    // -------------------------------------------------------------------------
    // Issue #70 — reputation (delegated through proxy)
    // -------------------------------------------------------------------------

    pub fn get_source_reputation(env: Env, source: Address) -> Option<SourceReputation> {
        let rep = storage::get_source_reputation(&env, &source)?;
        Some(utils::apply_reputation_decay(&env, rep))
    }

    pub fn reset_reputation(
        env: Env,
        admin: Address,
        source: Address,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::remove_source_reputation(&env, &source);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Oracle operations delegated through proxy
    // -------------------------------------------------------------------------

    pub fn submit_price(
        env: Env,
        source: Address,
        asset: String,
        price: i128,
        decimals: u32,
        timestamp: u64,
    ) -> Result<PriceDataPoint, OracleError> {
        source.require_auth();

        if !storage::is_authorized_source(&env, &source) {
            return Err(OracleError::UnauthorizedSource);
        }

        // Issue #69: deviation guard
        if let Some(threshold_bps) = storage::get_deviation_threshold(&env) {
            if let Some(prev) = storage::get_latest_price(&env, &asset) {
                if utils::deviation_exceeds(price, prev.price, threshold_bps) {
                    return Err(OracleError::PriceDeviationTooLarge);
                }
            }
        }

        // Issue #70: update reputation before overwriting latest price
        utils::update_reputation(&env, &source, price, &asset, timestamp);

        let data_point = PriceDataPoint {
            asset: asset.clone(),
            price,
            decimals,
            timestamp,
            source: source.clone(),
        };

        storage::set_latest_price(&env, &asset, &data_point);
        utils::append_history(&env, &asset, data_point.clone());

        env.events()
            .publish(("price_submitted", asset, source), (price, timestamp));

        Ok(data_point)
    }

    pub fn get_price(env: Env, asset: String) -> Option<AssetPrice> {
        let data_point = storage::get_latest_price(&env, &asset)?;
        let num_sources = storage::get_source_count(&env);
        let is_trusted = storage::is_trusted_asset(&env, &asset);

        Some(AssetPrice {
            asset: data_point.asset.clone(),
            price: data_point.price,
            decimals: data_point.decimals,
            price_usd: utils::calculate_usd_price(&env, &data_point.asset, data_point.price, data_point.decimals),
            timestamp: data_point.timestamp,
            source: data_point.source,
            num_sources,
            is_trusted,
        })
    }

    pub fn get_assets(env: Env) -> Vec<String> {
        storage::get_all_assets(&env)
    }

    pub fn get_price_history(env: Env, asset: String, limit: u32) -> Vec<PriceDataPoint> {
        let all_history = storage::get_price_history(&env, &asset);
        let len = all_history.len();
        let start = if len > limit { len - limit } else { 0 };
        let mut result: Vec<PriceDataPoint> = Vec::new(&env);
        for i in start..len {
            if let Some(dp) = all_history.get(i) {
                result.push_back(dp);
            }
        }
        result
    }

    pub fn add_oracle_source(
        env: Env,
        admin: Address,
        source: Address,
        name: String,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::add_source(&env, &source, &name);
        Ok(())
    }

    pub fn remove_oracle_source(
        env: Env,
        admin: Address,
        source: Address,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::remove_source(&env, &source);
        Ok(())
    }

    pub fn set_trusted_asset(
        env: Env,
        admin: Address,
        asset: String,
        trusted: bool,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::set_trusted_asset(&env, &asset, trusted);
        Ok(())
    }
}
