use core::str::FromStr;

use near_sdk::{
    near,
    serde::{Deserialize, Serialize},
};
use schemars::JsonSchema;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof};

mod vk;

/// ZK‑Email verifier contract (WASM) for `RecoverEmailCircuit`.
///
/// This contract exposes view methods that verify Groth16 proofs and
/// return a structured `VerificationResult` containing the verification
/// outcome and the human‑readable fields anchored in the circuit.
#[near(contract_state)]
#[derive(Default)]
pub struct ZkEmailVerifier;

#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct VerificationResult {
    pub verified: bool,
    pub account_id: String,
    pub new_public_key: String,
    pub from_address: String,
    pub email_timestamp_ms: Option<u64>,
}

#[near]
impl ZkEmailVerifier {
    #[init]
    pub fn new() -> Self {
        // In the future we may precompute and cache a PreparedVerifyingKey here.
        Self
    }

    /// Verify a Groth16 proof for RecoverEmailCircuit.
    ///
    /// This is a scaffold: it parses the proof and public inputs and
    /// then calls `ark_groth16::verify_proof`. The actual verification
    /// key is still provided by the stub in `vk::verifying_key()`.
    pub fn verify(&self, proof: ProofInput, public_inputs: Vec<String>) -> VerificationResult {
        // NOTE: This will panic until vk::verifying_key() is implemented.
        let vk = vk::verifying_key();
        let pvk = prepare_verifying_key(&vk);

        let proof_ark = match parse_proof(proof) {
            Ok(p) => p,
            Err(_) => {
                return VerificationResult {
                    verified: false,
                    account_id: String::new(),
                    new_public_key: String::new(),
                    from_address: String::new(),
                    email_timestamp_ms: None,
                };
            }
        };

        let inputs_ark = match parse_public_inputs(public_inputs) {
            Ok(v) => v,
            Err(_) => {
                return VerificationResult {
                    verified: false,
                    account_id: String::new(),
                    new_public_key: String::new(),
                    from_address: String::new(),
                    email_timestamp_ms: None,
                };
            }
        };

        let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof_ark, &inputs_ark)
            .unwrap_or(false);

        // If the proof didn't verify, return a simple negative result.
        if !verified {
            return VerificationResult {
                verified: false,
                account_id: String::new(),
                new_public_key: String::new(),
                from_address: String::new(),
                email_timestamp_ms: None,
            };
        }

        // Attempt to decode the packed substrings from the public inputs.
        let mut account_id = String::new();
        let mut new_public_key = String::new();
        let mut from_address = String::new();
        let mut email_timestamp_ms = None;

        if inputs_ark.len() >= EXPECTED_PUBLIC_LEN {
            let account_chunks = &inputs_ark[ACCOUNT_OFFSET..ACCOUNT_OFFSET + PACKED_SUBSTRING_FIELD_LEN];
            let new_pk_chunks =
                &inputs_ark[NEW_PK_OFFSET..NEW_PK_OFFSET + PACKED_SUBSTRING_FIELD_LEN];
            let from_chunks = &inputs_ark[FROM_OFFSET..FROM_OFFSET + PACKED_SUBSTRING_FIELD_LEN];
            let ts_chunks =
                &inputs_ark[TIMESTAMP_OFFSET..TIMESTAMP_OFFSET + PACKED_SUBSTRING_FIELD_LEN];

            if let Ok(s) = unpack_field_chunks_to_str(account_chunks) {
                account_id = s;
            }
            if let Ok(s) = unpack_field_chunks_to_str(new_pk_chunks) {
                new_public_key = s;
            }
            if let Ok(s) = unpack_field_chunks_to_str(from_chunks) {
                from_address = s;
            }
            if let Ok(ts_str) = unpack_field_chunks_to_str(ts_chunks) {
                email_timestamp_ms = parse_email_timestamp_to_unix_ms(&ts_str);
            }
        }

        VerificationResult {
            verified: true,
            account_id,
            new_public_key,
            from_address,
            email_timestamp_ms,
        }
    }

    /// Verify a Groth16 proof and additionally bind the public signals corresponding to:
    /// - account_id
    /// - new_public_key
    /// - from_email
    /// - timestamp (Date: header substring)
    ///
    /// The circuit packs these three substrings from the DKIM‑verified header using
    /// PackByteSubArray (255 bytes / 31 bytes per field = 9 field elements each),
    /// appended after the public `pubkey` and `signature` inputs.
    pub fn verify_with_binding(
        &self,
        proof: ProofInput,
        public_inputs: Vec<String>,
        account_id: String,
        new_public_key: String,
        from_email: String,
        timestamp: String,
    ) -> VerificationResult {
        let mut result = VerificationResult {
            verified: false,
            account_id: account_id.clone(),
            new_public_key: new_public_key.clone(),
            from_address: from_email.clone(),
            email_timestamp_ms: parse_email_timestamp_to_unix_ms(&timestamp),
        };

        let vk = vk::verifying_key();
        let pvk = prepare_verifying_key(&vk);

        let proof_ark = match parse_proof(proof) {
            Ok(p) => p,
            Err(_) => return result,
        };

        let inputs_ark = match parse_public_inputs(public_inputs.clone()) {
            Ok(v) => v,
            Err(_) => return result,
        };

        if inputs_ark.len() != EXPECTED_PUBLIC_LEN {
            return result;
        }

        let account_chunks = match pack_str_to_field_chunks(&account_id) {
            Ok(c) => c,
            Err(_) => return result,
        };
        let new_pk_chunks = match pack_str_to_field_chunks(&new_public_key) {
            Ok(c) => c,
            Err(_) => return result,
        };
        let from_chunks = match pack_str_to_field_chunks(&from_email) {
            Ok(c) => c,
            Err(_) => return result,
        };
        let timestamp_chunks = match pack_str_to_field_chunks(&timestamp) {
            Ok(c) => c,
            Err(_) => return result,
        };

        // Sanity: all packed substrings must have the expected length.
        if account_chunks.len() != PACKED_SUBSTRING_FIELD_LEN
            || new_pk_chunks.len() != PACKED_SUBSTRING_FIELD_LEN
            || from_chunks.len() != PACKED_SUBSTRING_FIELD_LEN
            || timestamp_chunks.len() != PACKED_SUBSTRING_FIELD_LEN
        {
            return result;
        }

        // Check account_id binding.
        for i in 0..PACKED_SUBSTRING_FIELD_LEN {
            if inputs_ark[ACCOUNT_OFFSET + i] != account_chunks[i] {
                return result;
            }
        }

        // Check new_public_key binding.
        for i in 0..PACKED_SUBSTRING_FIELD_LEN {
            if inputs_ark[NEW_PK_OFFSET + i] != new_pk_chunks[i] {
                return result;
            }
        }

        // Check from_email binding.
        for i in 0..PACKED_SUBSTRING_FIELD_LEN {
            if inputs_ark[FROM_OFFSET + i] != from_chunks[i] {
                return result;
            }
        }

        // Check timestamp binding.
        for i in 0..PACKED_SUBSTRING_FIELD_LEN {
            if inputs_ark[TIMESTAMP_OFFSET + i] != timestamp_chunks[i] {
                return result;
            }
        }

        result.verified = Groth16::<Bn254>::verify_proof(
            &pvk,
            &proof_ark,
            &inputs_ark
        ).unwrap_or(false);

        result
    }
}

/// Input format for a Groth16 proof, roughly mirroring snarkjs's `proof.json`.
#[derive(Deserialize, Serialize)]
#[serde(crate = "near_sdk::serde")]
#[derive(JsonSchema)]
pub struct ProofInput {
    /// pi_a: [Ax, Ay, Az]; we use Ax, Ay and assume Az = 1.
    pub pi_a: [String; 3],
    /// pi_b: [[Bx1, Bx0], [By1, By0], [Bz1, Bz0]]; we use the first two pairs.
    pub pi_b: [[String; 2]; 3],
    /// pi_c: [Cx, Cy, Cz]; we use Cx, Cy and assume Cz = 1.
    pub pi_c: [String; 3],
}

fn parse_fq(s: &str) -> Result<Fq, ()> {
    Fq::from_str(s).map_err(|_| ())
}

fn parse_fr(s: &str) -> Result<Fr, ()> {
    Fr::from_str(s).map_err(|_| ())
}

fn parse_fq2(c0: &str, c1: &str) -> Result<Fq2, ()> {
    let a0 = parse_fq(c0)?;
    let a1 = parse_fq(c1)?;
    Ok(Fq2::new(a0, a1))
}

fn parse_proof(input: ProofInput) -> Result<Proof<Bn254>, ()> {
    // G1 A
    let ax = parse_fq(&input.pi_a[0])?;
    let ay = parse_fq(&input.pi_a[1])?;
    let a = G1Affine::new_unchecked(ax, ay);

    // G2 B
    // snarkjs bn128 convention: pi_b[0] and pi_b[1] are Fq2 coords.
    let bx = parse_fq2(&input.pi_b[0][0], &input.pi_b[0][1])?;
    let by = parse_fq2(&input.pi_b[1][0], &input.pi_b[1][1])?;
    let b = G2Affine::new_unchecked(bx, by);

    // G1 C
    let cx = parse_fq(&input.pi_c[0])?;
    let cy = parse_fq(&input.pi_c[1])?;
    let c = G1Affine::new_unchecked(cx, cy);

    Ok(Proof::<Bn254> { a, b, c })
}

fn parse_public_inputs(inputs: Vec<String>) -> Result<Vec<Fr>, ()> {
    inputs.into_iter().map(|s| parse_fr(&s)).collect()
}

/// Number of bytes packed into a single field element in PackBytes / PackByteSubArray.
/// Must match MAX_BYTES_IN_FIELD() for BN254 in @zk-email/circuits.
const PACKED_BYTES_PER_FIELD: usize = 31;

/// Maximum number of bytes we pack for a subject or from-email substring.
/// Must match the `max_*_len` constants used in `RecoverEmailCircuit.circom` (255).
const MAX_PACKED_SUBSTRING_LEN: usize = 255;

/// Number of field elements used per packed substring (account_id, new_public_key, from_email, timestamp).
/// 255 bytes / 31 bytes per field = 9.
const PACKED_SUBSTRING_FIELD_LEN: usize = 9;

/// Layout constants for `RecoverEmailCircuit` public inputs:
/// [request_id_packed[9], account_id_packed[9], public_key_packed[9], from_email_packed[9], timestamp_packed[9], pubkey[17], signature[17]]
const PUBKEY_LEN: usize = 17;
const REQUEST_ID_OFFSET: usize = 0;
const ACCOUNT_OFFSET: usize = REQUEST_ID_OFFSET + PACKED_SUBSTRING_FIELD_LEN;
const NEW_PK_OFFSET: usize = ACCOUNT_OFFSET + PACKED_SUBSTRING_FIELD_LEN;
const FROM_OFFSET: usize = NEW_PK_OFFSET + PACKED_SUBSTRING_FIELD_LEN;
const TIMESTAMP_OFFSET: usize = FROM_OFFSET + PACKED_SUBSTRING_FIELD_LEN;
const EXPECTED_PUBLIC_LEN: usize = PACKED_SUBSTRING_FIELD_LEN * 5 + PUBKEY_LEN * 2;

fn pack_str_to_field_chunks(s: &str) -> Result<Vec<Fr>, ()> {
    let bytes = s.as_bytes();
    if bytes.len() > MAX_PACKED_SUBSTRING_LEN {
        return Err(());
    }

    let mut chunks = Vec::with_capacity(PACKED_SUBSTRING_FIELD_LEN);
    let base = Fr::from(256u64);

    for i in 0..PACKED_SUBSTRING_FIELD_LEN {
        let mut acc = Fr::from(0u64);
        let mut pow = Fr::from(1u64);

        for j in 0..PACKED_BYTES_PER_FIELD {
            let idx = i * PACKED_BYTES_PER_FIELD + j;
            if idx >= bytes.len() {
                break;
            }
            let b = Fr::from(bytes[idx] as u64);
            acc += b * pow;
            pow *= base;
        }

        chunks.push(acc);
    }

    Ok(chunks)
}

fn unpack_field_chunks_to_str(chunks: &[Fr]) -> Result<String, ()> {
    let mut bytes = Vec::with_capacity(chunks.len() * PACKED_BYTES_PER_FIELD);

    for fr in chunks {
        let bigint = fr.into_bigint();
        let mut limb_bytes = bigint.to_bytes_le();
        if limb_bytes.len() < PACKED_BYTES_PER_FIELD {
            limb_bytes.resize(PACKED_BYTES_PER_FIELD, 0);
        }
        bytes.extend_from_slice(&limb_bytes[..PACKED_BYTES_PER_FIELD]);
    }

    // Trim trailing zero padding introduced during packing.
    while matches!(bytes.last(), Some(0)) {
        bytes.pop();
    }

    String::from_utf8(bytes).map_err(|_| ())
}

fn parse_email_timestamp_to_unix_ms(s: &str) -> Option<u64> {
    // Expect formats like: "Sun, 30 Nov 2025 17:37:38 +0900"
    let trimmed = s.trim();
    let after_comma = match trimmed.split_once(',') {
        Some((_, rest)) => rest.trim_start(),
        None => trimmed,
    };

    let parts: Vec<&str> = after_comma.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    let day: u32 = parts[0].parse().ok()?;
    let month_str = parts[1];
    let year: i32 = parts[2].parse().ok()?;

    let month = match month_str {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };

    let time_parts: Vec<&str> = parts[3].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: u32 = time_parts[0].parse().ok()?;
    let minute: u32 = time_parts[1].parse().ok()?;
    let second: u32 = time_parts[2].parse().ok()?;

    let offset_str = parts[4];
    if offset_str.len() < 3 {
        return None;
    }
    let (sign_char, rest) = offset_str.split_at(1);
    let sign = match sign_char {
        "+" => 1i64,
        "-" => -1i64,
        _ => return None,
    };
    if rest.len() != 4 {
        return None;
    }
    let offset_hours: i64 = rest[0..2].parse().ok()?;
    let offset_minutes: i64 = rest[2..4].parse().ok()?;
    let offset_secs: i64 = sign * (offset_hours * 3600 + offset_minutes * 60);

    // Compute days since Unix epoch (1970-01-01).
    if year < 1970 {
        return None;
    }

    fn is_leap_year(y: i32) -> bool {
        (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
    }

    const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    fn days_in_month(year: i32, month: u32) -> u32 {
        if month == 2 && is_leap_year(year) {
            29
        } else {
            DAYS_IN_MONTH[(month - 1) as usize]
        }
    }

    if month == 0 || month > 12 {
        return None;
    }
    if day == 0 || day > days_in_month(year, month) {
        return None;
    }

    let mut days: i64 = 0;
    let mut y = 1970;
    while y < year {
        days += if is_leap_year(y) { 366 } else { 365 };
        y += 1;
    }

    let mut m = 1;
    while m < month {
        days += days_in_month(year, m) as i64;
        m += 1;
    }

    days += (day - 1) as i64;

    let seconds_local: i64 =
        days * 86_400 + (hour as i64) * 3_600 + (minute as i64) * 60 + (second as i64);

    // Offset is "local = UTC + offset", so UTC = local - offset.
    let seconds_utc = seconds_local - offset_secs;
    if seconds_utc < 0 {
        return None;
    }

    Some(seconds_utc as u64 * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    #[test]
    fn snarkjs_proof_verifies_with_generated_vk() {
        // Load proof.json and public.json from the contract tests/proofs directory.
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

        let vk = vk::verifying_key();
        let pvk = prepare_verifying_key(&vk);

        let proof_ark = parse_proof(proof_input).expect("failed to parse proof into ark type");
        let inputs_ark =
            parse_public_inputs(public_inputs).expect("failed to parse public inputs into Fr");

        let ok =
            Groth16::<Bn254>::verify_proof(&pvk, &proof_ark, &inputs_ark).expect("verify_proof failed");
        assert!(ok, "snarkjs proof did not verify under generated verifying key");
    }
}
