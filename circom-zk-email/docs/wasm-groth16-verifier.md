## Groth16 Verifier in NEAR WASM (Arkworks)

This repo implements a small, anchored DKIM email circuit in Circom, a fast Groth16 prover, and a NEAR WASM verifier using Arkworks, with a one-shot vk generator linking the two worlds.

Features:
- Circom circuit: `RecoverEmailCircuit.circom`
- Prover: snarkjs (or rapidsnark) over BN254
- On-chain verifier: NEAR contract using Arkworks (`ark-groth16`, `ark-bn254`)
- Verifying key (VK) generator for contract: Rust binary `vk-generator` (crate in `zk-email-verifier-contract/copy-vk-to-contract`)

### Pipeline overview

1. **Circom + snarkjs (off-chain)**
   - Compile:
     - `circom-zk-email/circuits/RecoverEmailCircuit.circom` → `build/RecoverEmailCircuit.r1cs`, `build/RecoverEmailCircuit_js/RecoverEmailCircuit.wasm`
   - Setup & prove:
     - `build/RecoverEmailCircuit.zkey` (Groth16 proving + verifying key)
     - `verification_key.json` (exported from `.zkey`)
     - `proof.json`, `public.json` (Groth16 proof + public signals)
   - All driven by:
     - `circom-zk-email/scripts/generateWitness.ts`
     - `circom-zk-email/scripts/prove.ts`
     - `circom-zk-email/scripts/verify.ts`

2. **Anchored manual header verification (in-circuit)**

`RecoverEmailCircuit` embeds `EmailVerifier` from `@zk-email/circuits` and then enforces three anchored patterns over the DKIM‑verified header:

- **Subject line**
  - Pattern: `subject:recover <account_id> ed25519:<public_key>`
  - Checks:
    - Anchor: if `subject_start_idx != 0`, the two bytes before it must be `\r\n`.
    - Static prefix: `"subject:recover "` via `SelectSubArray`.
    - Structure: account id, a single space, `"ed25519:"`, then public key.
  - Outputs:
    - `account_id_packed[9]`
    - `public_key_packed[9]`

- **From header**
  - Pattern: `from: ... <email>` (display name + address)
  - Checks:
    - Anchor: if `from_start_idx != 0`, the two bytes before it must be `\r\n`.
    - Static prefix: `"from:"` via `SelectSubArray`.
    - Range check: no `\r`/`\n` between `"from:"` and the start of the email address:
      - Implemented as `(byte - 13) * (byte - 10) != 0` over the gap.
  - Outputs:
    - `from_email_packed[9]`

- **Date header**
  - Pattern: `date: <timestamp>`
  - Checks:
    - Anchor: if `date_start_idx != 0`, the two bytes before it must be `\r\n`.
    - Static prefix: `"date:"` via `SelectSubArray`.
  - Outputs:
    - `timestamp_packed[9]`

These constraints ensure the prover can’t point indices into fake headers or comments; all three values are bound to real DKIM‑verified header lines.

3. **VK generation (Rust tool)**

- Crate: `vk-generator` in `zk-email-verifier-contract/copy-vk-to-contract`.
- Binary reads:
  - `circom-zk-email/build/verification_key.json` (snarkjs format)
- Parses:
  - G1/G2 coordinates into `ark_bn254::{Fq, Fq2, G1Affine, G2Affine}`
  - `IC[]` into `gamma_abc_g1: Vec<G1Affine>`
- Validates:
  - Constructs an `ark_groth16::VerifyingKey<Bn254>`
  - Calls `prepare_verifying_key` to ensure consistency
- Emits:
  - `zk-email-verifier-contract/src/vk.rs` with a concrete
    `pub fn verifying_key() -> VerifyingKey<Bn254>` that reconstructs the vk from constants.

Command (from repo root, via `circom-zk-email/package.json`):

```bash
cd circom-zk-email
pnpm generate-vk-contract   # runs vk-generator and overwrites zk-email-verifier-contract/src/vk.rs
```

4. **NEAR contract (Arkworks verifier)**

- Crate: `zk-email-verifier-contract`
- Dependencies:
  - `near-sdk = "5.18.1"`
  - `ark-ff`, `ark-ec`, `ark-serialize`, `ark-bn254`, `ark-groth16` (all `0.5`, `default-features = false`, `features = ["std"/"curve"]` as appropriate)

Key pieces in `src/lib.rs`:

- Imports:

```rust
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_groth16::{prepare_verifying_key, Groth16, Proof};
mod vk; // generated verifying_key()
```

- Contract type:

```rust
#[near(contract_state)]
#[derive(Default)]
pub struct ZkEmailVerifier;
```

- Proof input type (matching snarkjs `proof.json`):

```rust
#[derive(Deserialize, Serialize)]
#[serde(crate = "near_sdk::serde")]
#[derive(JsonSchema)]
pub struct ProofInput {
    pub pi_a: [String; 3],
    pub pi_b: [[String; 2]; 3],
    pub pi_c: [String; 3],
}
```

- Parsing helpers:
  - `parse_fq`, `parse_fr`, `parse_fq2`
  - `parse_proof(ProofInput) -> Proof<Bn254>`
  - `parse_public_inputs(Vec<String>) -> Vec<Fr>`

- Base `verify` method:

```rust
pub fn verify(&self, proof: ProofInput, public_inputs: Vec<String>) -> bool {
    let vk = vk::verifying_key();
    let pvk = prepare_verifying_key(&vk);

    let proof_ark = match parse_proof(proof) { Ok(p) => p, Err(_) => return false };
    let inputs_ark = match parse_public_inputs(public_inputs) { Ok(v) => v, Err(_) => return false };

    Groth16::<Bn254>::verify_proof(&pvk, &proof_ark, &inputs_ark).unwrap_or(false)
}
```

- `verify_with_binding` method:
  - Recomputes packed field elements from:
    - `account_id: String`
    - `new_public_key: String`
    - `from_email: String`
    - `timestamp: String`
  - Uses the same 31‑bytes‑per‑field packing as `RecoverEmailCircuit` (`PackByteSubArray`).
  - Checks these against the corresponding slots in `public_inputs`:
    - `account_id_packed[9]`
    - `public_key_packed[9]`
    - `from_email_packed[9]`
    - `timestamp_packed[9]`
  - Returns `true` only if both:
    - Groth16 verification passes, and
    - All four packed substrings match.

This gives an on-chain API that not only verifies the proof, but also cryptographically binds the human-readable `account_id`, `new_public_key`, `from_email`, and `timestamp` to the DKIM‑verified email.

5. **Tests**

- Unit test in `zk-email-verifier-contract/src/lib.rs`:
  - Loads `zk-email-verifier-contract/proofs/{proof,public}.json`.
  - Parses into `ProofInput` and `Vec<String>`.
  - Asserts `Groth16::verify_proof` with `vk::verifying_key()` returns `true`.

- Integration tests in `zk-email-verifier-contract/tests`:
  - `snarkjs_proof_integration.rs`:
    - Uses the contract API (`ZkEmailVerifier::new().verify`) on the same proofs.
  - `near_contract_integration.rs`:
    - Spins up NEAR sandbox with `near-workspaces`.
    - Deploys the compiled WASM.
    - Calls `new` and then `verify` as a view method.

Both confirm that the Arkworks verifier + generated `vk.rs` accept the same proofs as snarkjs.


