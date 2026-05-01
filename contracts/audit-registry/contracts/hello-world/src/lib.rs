#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    BytesN, Env, String,
};

/// Main audit registry contract entry type.
#[contract]
pub struct AuditRegistry;

/// A single immutable audit record stored on-chain.
#[derive(Clone)]
#[contracttype]
pub struct AuditRecord {
    /// SHA-256 hash of the audited contract source.
    pub contract_hash: BytesN<32>,
    /// SHA-256 hash of the generated PDF report.
    pub report_hash: BytesN<32>,
    /// Risk score in the range 0..=100.
    pub risk_score: u32,
    /// IPFS CID where the full PDF report is stored.
    pub ipfs_cid: String,
    /// Ledger timestamp when the audit was recorded.
    pub timestamp: u64,
    /// Address that submitted this audit.
    pub auditor: Address,
    /// Number of anomalies found during dynamic analysis (0 when not performed).
    pub dynamic_anomalies_count: u32,
    /// Risk adjustment from dynamic analysis (0 when not performed).
    pub dynamic_risk_adjustment: i32,
}

/// Event payload emitted whenever a new audit is recorded.
#[derive(Clone)]
#[contracttype]
pub struct AuditRecordedEvent {
    pub contract_hash: BytesN<32>,
    pub report_hash: BytesN<32>,
    pub risk_score: u32,
    pub ipfs_cid: String,
    pub timestamp: u64,
    pub auditor: Address,
}

/// Persistent storage keys used by this contract.
#[derive(Clone)]
#[contracttype]
enum DataKey {
    Audit(BytesN<32>),
    TotalAudits,
}

/// Contract-specific errors.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    InvalidRiskScore = 1,
    EmptyIpfsCid = 2,
    AuditAlreadyExists = 3,
    AuditNotFound = 4,
    ArithmeticOverflow = 5,
}

#[contractimpl]
impl AuditRegistry {
    /// Records a new audit for a contract hash.
    ///
    /// Requirements:
    /// - `risk_score` must be <= 100
    /// - `ipfs_cid` must be non-empty
    /// - a record for `contract_hash` must not already exist
    /// - `auditor` must authorize this transaction
    pub fn record_audit(
        env: Env,
        auditor: Address,
        contract_hash: BytesN<32>,
        report_hash: BytesN<32>,
        risk_score: u32,
        ipfs_cid: String,
        dynamic_anomalies_count: u32,
        dynamic_risk_adjustment: i32,
    ) {
        if risk_score > 100 {
            panic_with_error!(&env, Error::InvalidRiskScore);
        }
        if ipfs_cid.len() == 0 {
            panic_with_error!(&env, Error::EmptyIpfsCid);
        }

        let key = DataKey::Audit(contract_hash.clone());
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, Error::AuditAlreadyExists);
        }

        // Require the submitting account to authorize this transaction.
        auditor.require_auth();

        let timestamp = env.ledger().timestamp();
        let record = AuditRecord {
            contract_hash: contract_hash.clone(),
            report_hash: report_hash.clone(),
            risk_score,
            ipfs_cid: ipfs_cid.clone(),
            timestamp,
            auditor: auditor.clone(),
            dynamic_anomalies_count,
            dynamic_risk_adjustment,
        };
        env.storage().persistent().set(&key, &record);

        let total_key = DataKey::TotalAudits;
        let current_total = env.storage().persistent().get::<_, u64>(&total_key).unwrap_or(0);
        let updated_total = current_total
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(&env, Error::ArithmeticOverflow));
        env.storage().persistent().set(&total_key, &updated_total);

        // Emit event for indexers / off-chain consumers.
        let event = AuditRecordedEvent {
            contract_hash: contract_hash.clone(),
            report_hash,
            risk_score,
            ipfs_cid,
            timestamp,
            auditor,
        };
        env.events()
            .publish((symbol_short!("audit_rec"), contract_hash), event);
    }

    /// Retrieves the audit record for a given contract hash.
    pub fn get_audit(env: Env, contract_hash: BytesN<32>) -> AuditRecord {
        let key = DataKey::Audit(contract_hash);
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::AuditNotFound))
    }

    /// Returns true if a contract hash already has an audit record.
    pub fn has_been_audited(env: Env, contract_hash: BytesN<32>) -> bool {
        let key = DataKey::Audit(contract_hash);
        env.storage().persistent().has(&key)
    }

    /// Returns the total number of audits recorded in this registry.
    pub fn get_total_audits(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get::<_, u64>(&DataKey::TotalAudits)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod test;
