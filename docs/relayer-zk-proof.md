# Relayer → ZK Prover Server Integration

This document describes how a relayer or backend server can call the
`circom-zk-email` prover HTTP API with a DKIM‑signed email and obtain
Groth16 proofs suitable for on‑chain verification.

The prover server wraps the `RecoverEmailCircuit` Circom circuit and the
snarkjs/rapidsnark proving pipeline.

## 1. Running the prover server

You can run the prover either directly with Node or via Docker.

### Local Node (dev)

From the repo root:

```bash
cd circom-zk-email
npm install          # first time only (or: pnpm install)
npm run dev:server   # or: npm run start:server
```

This starts an Express server on port `5588` by default (override with `PORT`).

### Docker

From the repo root:

```bash
just docker-build
just docker-run
```

This builds an image that includes:

- Node 22 runtime
- rapidsnark Groth16 prover
- `circom-zk-email/` and `zk-email-verifier-contract/`
- The Express prover server as the container entrypoint

## 2. API endpoint

The prover exposes a single JSON endpoint for generating a proof:

- **Method:** `POST`
- **Path:** `/prove-email`
- **Content-Type:** `application/json`

There is also a simple health check endpoint:

- **Method:** `GET`
- **Path:** `/healthz`

Base URL examples:

- Local Node: `http://localhost:5588/prove-email`
- Docker: `http://localhost:5588/prove-email` (after `docker run -p 5588:5588`)

## 3. Request shape

Body JSON:

```json
{
  "rawEmail": "<full .eml contents as a UTF-8 string>"
}
```

Notes:

- `rawEmail` must be the **entire original email** as received by your mail
  provider, including all headers and MIME parts (exact bytes matter for DKIM).
- The server currently accepts payloads up to **256 KB**.
- The circuit expects a `Subject:` line matching:
  - `Subject: recover-<request_id> <account_id> ed25519:<new_public_key>`
- The pipeline DKIM‑verifies the headers and then parses the DKIM‑verified
  `Subject:`, `From:`, and `Date:` header lines to generate the witness.
- The prover server writes intermediate artifacts to fixed paths (e.g.
  `circom-zk-email/emls/api_input.eml`, `circom-zk-email/input.json`,
  `circom-zk-email/witness.wtns`, `circom-zk-email/proofs/*`), so it is not safe
  to run multiple `/prove-email` requests concurrently without additional
  isolation.

Example `curl`:

```bash
jq -n --rawfile eml circom-zk-email/emls/gmail_reset_full.eml '{rawEmail: $eml}' | \
  curl -X POST http://localhost:5588/prove-email \
    -H 'Content-Type: application/json' \
    --data-binary @-
```

Or in pseudocode:

```ts
const rawEmail = fs.readFileSync("path/to/email.eml", "utf8");
const res = await fetch("http://localhost:5588/prove-email", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ rawEmail }),
});
const { proof, publicSignals } = await res.json();
```

## 4. Response shape

On success (`200 OK`), the server returns:

```json
{
  "proof": {
    "pi_a": ["...", "...", "..."],
    "pi_b": [["...", "..."], ["...", "..."], ["...", "..."]],
    "pi_c": ["...", "...", "..."]
  },
  "publicSignals": ["...", "...", "..."]
}
```

Fields:

- `proof` matches snarkjs `proof.json` for a BN254 Groth16 proof:
  - `pi_a`: G1 point A (three coordinates; only first two are used)
  - `pi_b`: G2 point B as Fq2 coordinates
  - `pi_c`: G1 point C (three coordinates; only first two are used)
- `publicSignals` matches snarkjs `public.json` (array of decimal strings):
  - Each entry is a scalar field element (`Fr` on BN254) encoded as a base‑10 string.

For `RecoverEmailCircuit`, the `publicSignals` layout is:

1. `request_id_packed[9]` (from `Subject: recover-<request_id> ...`)
2. `account_id_packed[9]`
3. `public_key_packed[9]` (the new Ed25519 public key)
4. `from_email_packed[9]`
5. `timestamp_packed[9]` (the `Date:` header substring)
6. `pubkey[17]` (RSA public key for DKIM)
7. `signature[17]` (RSA signature over the canonicalized header)

Each `*_packed[9]` is the 255‑byte substring packed into 9 field elements
using base‑256 (31 bytes per field).

Note: if you are verifying on‑chain, your verifier must use the same public
signal ordering/length. In this repo, `zk-email-verifier-contract` may need to
be updated to account for the leading `request_id_packed[9]`.

## 5. Error responses

The server returns standard HTTP error codes:

- `400 Bad Request`
  - When `rawEmail` is missing or not a non‑empty string.
  - Shape:
    ```json
    { "error": "rawEmail (string) is required" }
    ```

- `500 Internal Server Error`
  - When any step in the pipeline fails:
    - Email parsing / regexp extraction
    - Witness generation
    - Prover (snarkjs / rapidsnark)
  - Shape:
    ```json
    { "error": "proving_failed" }
    ```

In both cases, additional details are logged to the server’s stderr/stdout.

## 6. Relayer workflow summary

For a relayer service that wants to verify password‑recovery emails and submit
proofs on‑chain, the typical flow is:

1. Receive a raw `.eml` from a trusted channel (e.g. webhook from your
   mail provider, or a client upload that preserves the original bytes).
2. POST `rawEmail` to the prover server’s `/prove-email` endpoint.
3. Receive `{ proof, publicSignals }`.
4. Extract the human‑readable fields by:
   - Either relying on the verifier contract’s `verify_with_binding` method
     (passing the strings you expect: `account_id`, `new_public_key`,
     `from_email`, `timestamp`), or
   - Unpacking `publicSignals` client‑side if you need to inspect them.
5. Submit the proof and bound values to the on‑chain verifier (e.g. NEAR
   `ZkEmailVerifier::verify_with_binding`) or to a TEE verifier, depending
   on your architecture.

This gives you an end‑to‑end path from “email received by relayer” to
“zero‑knowledge proof + public signals ready for on‑chain verification”.
