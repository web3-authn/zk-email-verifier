use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::json;
use zk_email_verifier_contract::{ProofInput, VerificationResult};

/// Response from the Docker prover's /prove-email endpoint
#[derive(Deserialize)]
struct ProveResponse {
    proof: ProofInput,
    #[serde(rename = "publicSignals")]
    public_signals: Vec<String>,
}

/// End-to-end test that:
/// 1. Calls the Docker ZK prover API to generate a proof
/// 2. Deploys the contract to NEAR sandbox
/// 3. Verifies the proof on-chain
///
/// Prerequisites:
/// - Docker prover must be running: `just docker-run-prover`
/// - Contract WASM must be built: `just cargo-build`
#[tokio::test]
async fn e2e_generate_and_verify_proof() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== E2E Test: Generate Proof -> Verify on NEAR Sandbox ===\n");

    // Step 1: Generate proof via Docker prover API
    println!("Step 1: Generating proof via Docker ZK prover...");
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let eml_path = Path::new(manifest_dir)
        .join("../circom-zk-email/emls/gmail_reset_full.eml");
    let raw_eml = fs::read_to_string(&eml_path)
        .expect("failed to read gmail_reset_full.eml");

    let client = reqwest::Client::new();
    let response = client
        .post("http://localhost:5588/prove-email")
        .json(&json!({ "rawEmail": raw_eml }))
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        panic!("Failed to generate proof: {}", error_text);
    }

    let prove_response: ProveResponse = response.json().await?;
    println!("Proof generated successfully\n");

    // Step 2: Save proof to tests/proofs directory
    println!("Step 2: Saving proof to tests/proofs/...");
    let proofs_dir = Path::new(manifest_dir).join("tests").join("proofs");
    fs::create_dir_all(&proofs_dir)?;

    let proof_json = serde_json::to_string_pretty(&prove_response.proof)?;
    let public_json = serde_json::to_string_pretty(&prove_response.public_signals)?;

    fs::write(proofs_dir.join("proof.json"), proof_json)?;
    fs::write(proofs_dir.join("public.json"), public_json)?;
    println!("Proof saved to: {:?}", proofs_dir);
    println!("  - proof.json");
    println!("  - public.json\n");

    // Step 3: Deploy contract to NEAR sandbox
    println!("Step 3: Deploying contract to NEAR sandbox...");
    let worker = near_workspaces::sandbox().await?;

    let wasm_path = Path::new(manifest_dir)
        .join("../target/near/zk_email_verifier_contract/zk_email_verifier_contract.wasm");
    let wasm_bytes = fs::read(&wasm_path).expect(
        "failed to read compiled contract WASM; did you run `just cargo-build`?",
    );

    let contract = worker.dev_deploy(&wasm_bytes).await?;
    println!("Contract deployed to: {}", contract.id());

    // Initialize the contract
    contract
        .call("new")
        .args_json(json!({}))
        .transact()
        .await?
        .into_result()?;
    println!("Contract initialized\n");

    // Step 4: Verify proof on-chain
    println!("Step 4: Verifying proof on NEAR sandbox...");
    let res = contract
        .call("verify")
        .args_json(json!({
            "proof": prove_response.proof,
            "public_inputs": prove_response.public_signals,
        }))
        .view()
        .await?;

    let result: VerificationResult = res.json()?;

    println!("\n=== Verification Result ===");
    println!("Verified: {}", result.verified);
    println!("Account ID: {}", result.account_id);
    println!("New Public Key: {}", result.new_public_key);
    println!("From Address: {}", result.from_address);
    if let Some(ts) = result.email_timestamp_ms {
        println!("Email Timestamp: {} ms", ts);
    }

    assert!(
        result.verified,
        "on-chain verify returned false for generated proof"
    );

    Ok(())
}
