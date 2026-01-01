use std::{fs, path::Path};

use sha2::{Digest, Sha256};
use zk_email_verifier_contract::{ProofInput, VerificationResult, ZkEmailVerifier};

fn expected_from_address_hash(from_email: &str, account_id: &str) -> Vec<u8> {
    let canonical_from = from_email.trim().to_ascii_lowercase();
    let account_id_lower = account_id.trim().to_ascii_lowercase();
    let preimage = format!("{canonical_from}|{account_id_lower}");
    Sha256::digest(preimage.as_bytes()).to_vec()
}

/// Unit test that checks the contract `verify` method
/// against the existing snarkjs artifacts in tests/proofs.
#[test]
fn contract_verify_proof() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let proofs_dir = Path::new(manifest_dir).join("tests").join("proofs");

    let proof_json = fs::read_to_string(proofs_dir.join("proof.json"))
        .expect("failed to read proof.json");
    let public_json = fs::read_to_string(proofs_dir.join("public.json"))
        .expect("failed to read public.json");

    let proof_input: ProofInput =
        serde_json::from_str(&proof_json).expect("failed to parse proof.json into ProofInput");
    let public_inputs: Vec<String> =
        serde_json::from_str(&public_json).expect("failed to parse public.json");

    let contract = ZkEmailVerifier::new();
    let res: VerificationResult = contract.verify(proof_input, public_inputs);
    assert!(res.verified, "contract.verify returned false for snarkjs proof");

    // Sender email is kept private; only its salted hash is exposed.
    let expected_hash = expected_from_address_hash("n6378056@gmail.com", &res.account_id);
    assert_eq!(res.from_address_hash, expected_hash);
}

/// Unit test that checks the contract `verify_with_binding` method
/// against the existing snarkjs artifacts in tests/proofs, using the
/// account_id / new_public_key encoded in the sample email.
#[test]
fn unit_test_contract_verify_with_binding_snarkjs_proof() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let proofs_dir = Path::new(manifest_dir).join("tests").join("proofs");

    let proof_json = fs::read_to_string(proofs_dir.join("proof.json"))
        .expect("failed to read proof.json");
    let public_json = fs::read_to_string(proofs_dir.join("public.json"))
        .expect("failed to read public.json");

    let proof_input: ProofInput = serde_json::from_str(&proof_json)
        .expect("failed to parse proof.json into ProofInput");
    let public_inputs: Vec<String> = serde_json::from_str(&public_json)
        .expect("failed to parse public.json");

    // These values come from the sample email in
    // `circom-zk-email/emls/gmail_reset_full.eml`, which was used to
    // generate the witness/proof/public inputs.
    let account_id = "kerp30.w3a-v1.testnet".to_string();
    let new_public_key =
        "86mqiBdv45gM4c5uLmvT3TU4g7DAg6KLpuabBSFweigm".to_string();
    let timestamp = "Tue, 9 Dec 2025 17:13:23 +0900".to_string();
    let from_email = "n6378056@gmail.com";

    let contract = ZkEmailVerifier::new();
    let res: VerificationResult = contract.verify_with_binding(
        proof_input,
        public_inputs,
        account_id,
        new_public_key,
        timestamp,
    );
    assert!(
        res.verified,
        "contract.verify_with_binding returned false for snarkjs proof"
    );

    let expected_hash = expected_from_address_hash(from_email, &res.account_id);
    assert_eq!(res.from_address_hash, expected_hash);
}
