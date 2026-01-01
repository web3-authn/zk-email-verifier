use std::{fs, path::Path};

use serde_json::json;
use sha2::{Digest, Sha256};
use zk_email_verifier_contract::{ProofInput, VerificationResult};

fn expected_from_address_hash(from_email: &str, account_id: &str) -> Vec<u8> {
    let canonical_from = from_email.trim().to_ascii_lowercase();
    let account_id_lower = account_id.trim().to_ascii_lowercase();
    let preimage = format!("{canonical_from}|{account_id_lower}");
    Sha256::digest(preimage.as_bytes()).to_vec()
}

/// End-to-end style test that:
/// 1. Spins up a local NEAR sandbox node (via near-workspaces),
/// 2. Deploys the compiled zk-email-verifier-contract WASM,
/// 3. Calls `new` and then `verify` with the existing proof/public inputs,
/// 4. Asserts that the on-chain `verify` returns true.
///
/// Prerequisites:
/// - Build the contract to WASM before running this test, e.g.:
///     pnpm cargo:build
/// - Ensure the built WASM is located at:
///     ../target/wasm32-unknown-unknown/release/zk_email_verifier_contract.wasm
#[tokio::test]
async fn deploy_and_verify_proof() -> Result<(), Box<dyn std::error::Error>> {
    // Spin up a local sandbox worker.
    let worker = near_workspaces::sandbox().await?;

    // Locate the compiled WASM produced by `cargo near build`.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // Prefer the optimized artifact produced by `cargo near build`,
    // which is written under `target/near/<crate>/<crate>.wasm`.
    let wasm_path = Path::new(manifest_dir)
        .join("../target/near/zk_email_verifier_contract/zk_email_verifier_contract.wasm");
    let wasm_bytes = fs::read(&wasm_path).expect(
        "failed to read compiled contract WASM; did you run `pnpm cargo:build` (cargo near build)?",
    );

    // Deploy the contract.
    let contract = worker.dev_deploy(&wasm_bytes).await?;

    // Initialize the contract (calls `new()`).
    contract
        .call("new")
        .args_json(json!({}))
        .transact()
        .await?
        .into_result()?;

    // Load proof.json and public.json from the contract tests/proofs directory.
    let proofs_dir = Path::new(manifest_dir).join("tests").join("proofs");

    let proof_json =
        fs::read_to_string(proofs_dir.join("proof.json")).expect("failed to read proof.json");
    let public_json =
        fs::read_to_string(proofs_dir.join("public.json")).expect("failed to read public.json");

    let proof_input: ProofInput =
        serde_json::from_str(&proof_json).expect("failed to parse proof.json into ProofInput");
    let public_inputs: Vec<String> =
        serde_json::from_str(&public_json).expect("failed to parse public.json");

    // Call the on-chain `verify` view method.
    let res = contract
        .call("verify")
        .args_json(json!({
            "proof": proof_input,
            "public_inputs": public_inputs,
        }))
        .view()
        .await?;

    let result: VerificationResult = res.json()?;
    assert!(
        result.verified,
        "on-chain verify returned false for snarkjs proof"
    );

    Ok(())
}

/// End-to-end style test that:
/// 1. Spins up a local NEAR sandbox node (via near-workspaces),
/// 2. Deploys the compiled zk-email-verifier-contract WASM,
/// 3. Calls `new` and then `verify_with_binding` with the existing proof/public inputs
///    and the expected bound strings,
/// 4. Asserts that the on-chain `verify_with_binding` returns true.
#[tokio::test]
async fn deploy_and_verify_with_binding_snarkjs_proof_on_sandbox(
) -> Result<(), Box<dyn std::error::Error>> {
    let worker = near_workspaces::sandbox().await?;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let wasm_path = Path::new(manifest_dir)
        .join("../target/near/zk_email_verifier_contract/zk_email_verifier_contract.wasm");
    let wasm_bytes = fs::read(&wasm_path).expect(
        "failed to read compiled contract WASM; did you run `pnpm cargo:build` (cargo near build)?",
    );

    let contract = worker.dev_deploy(&wasm_bytes).await?;

    contract
        .call("new")
        .args_json(json!({}))
        .transact()
        .await?
        .into_result()?;

    let proofs_dir = Path::new(manifest_dir).join("tests").join("proofs");

    let proof_json =
        fs::read_to_string(proofs_dir.join("proof.json")).expect("failed to read proof.json");
    let public_json =
        fs::read_to_string(proofs_dir.join("public.json")).expect("failed to read public.json");

    let proof_input: ProofInput =
        serde_json::from_str(&proof_json).expect("failed to parse proof.json into ProofInput");
    let public_inputs: Vec<String> =
        serde_json::from_str(&public_json).expect("failed to parse public.json");

    // These values match the anchored substrings used to generate the proof.
    let account_id = "kerp30.w3a-v1.testnet".to_string();
    let new_public_key =
        "86mqiBdv45gM4c5uLmvT3TU4g7DAg6KLpuabBSFweigm".to_string();
    let from_email = "n6378056@gmail.com";
    let timestamp = "Tue, 9 Dec 2025 17:13:23 +0900".to_string();

    let res = contract
        .call("verify_with_binding")
        .args_json(json!({
            "proof": proof_input,
            "public_inputs": public_inputs,
            "account_id": account_id,
            "new_public_key": new_public_key,
            "timestamp": timestamp,
        }))
        .view()
        .await?;

    let result: VerificationResult = res.json()?;
    assert!(
        result.verified,
        "on-chain verify_with_binding returned false for snarkjs proof"
    );

    let expected_hash = expected_from_address_hash(from_email, &account_id);
    assert_eq!(result.from_address_hash, expected_hash);

    Ok(())
}
