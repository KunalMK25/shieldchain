#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env, String};

#[test]
fn test_record_and_read_audits() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(Contract, ());
    let client = ContractClient::new(&env, &contract_id);
    let auditor = Address::generate(&env);

    client.record_audit(
        &auditor,
        &String::from_str(&env, "hash_contract_v1"),
        &String::from_str(&env, "hash_report_v1"),
        &String::from_str(&env, "QmCid111"),
        &82,
    );
    client.record_audit(
        &auditor,
        &String::from_str(&env, "hash_contract_v1"),
        &String::from_str(&env, "hash_report_v2"),
        &String::from_str(&env, "QmCid222"),
        &21,
    );

    let latest = client.get_latest_audit(&String::from_str(&env, "hash_contract_v1"));
    assert_eq!(latest.risk_score, 21);
    assert_eq!(latest.report_hash, String::from_str(&env, "hash_report_v2"));

    let history = client.get_audit_history(&String::from_str(&env, "hash_contract_v1"));
    assert_eq!(history.len(), 2);
}
