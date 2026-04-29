#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, String, Vec};

#[contract]
pub struct Contract;

#[derive(Clone)]
#[contracttype]
pub struct AuditRecord {
    pub contract_hash: String,
    pub report_hash: String,
    pub ipfs_cid: String,
    pub risk_score: u32,
    pub timestamp: u64,
    pub auditor: Address,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    ContractAudits(String),
}

#[contractimpl]
impl Contract {
    pub fn record_audit(
        env: Env,
        auditor: Address,
        contract_hash: String,
        report_hash: String,
        ipfs_cid: String,
        risk_score: u32,
    ) {
        auditor.require_auth();
        let key = DataKey::ContractAudits(contract_hash.clone());
        let mut audits: Vec<AuditRecord> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env));

        let entry = AuditRecord {
            contract_hash,
            report_hash,
            ipfs_cid,
            risk_score,
            timestamp: env.ledger().timestamp(),
            auditor,
        };
        audits.push_back(entry);
        env.storage().persistent().set(&key, &audits);
        env.events()
            .publish((symbol_short!("recorded"),), audits.len());
    }

    pub fn get_latest_audit(env: Env, contract_hash: String) -> AuditRecord {
        let key = DataKey::ContractAudits(contract_hash);
        let audits: Vec<AuditRecord> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env));
        audits
            .get(audits.len() - 1)
            .unwrap_or_else(|| panic!("No audit history found"))
    }

    pub fn get_audit_history(env: Env, contract_hash: String) -> Vec<AuditRecord> {
        let key = DataKey::ContractAudits(contract_hash);
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env))
    }
}

mod test;
