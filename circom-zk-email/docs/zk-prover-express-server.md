# Plan: Express ZK Prover Server (circom-zk-email)

This document tracks the design and implementation progress for a simple Express.js server that wraps the RecoverEmailCircuit ZK prover, and the associated Docker image that bundles the prover + rapidsnark.

## Goals

- Provide an HTTP API to:
  - Accept a DKIM-signed email (`rawEmail`).
  - Run the existing Circom/snarkjs (or rapidsnark) pipeline to:
    - Generate the witness.
    - Produce `proof.json` and `public.json`.
  - Return `{ proof, publicSignals }` as JSON.
- Live entirely under `circom-zk-email/`.
- Provide a Docker image that:
  - Builds and installs rapidsnark (BN254 Groth16 prover).
  - Runs the Express server as the container entrypoint.

## Current Implementation Summary

### Express Server

- Location: `circom-zk-email/server/index.ts`
- Endpoints:
  - `GET /healthz` → `{ status: "ok" }`
  - `POST /prove-email`
    - Input JSON: `{ "rawEmail": "<full .eml contents as UTF-8 string>" }`
    - Pipeline:
      1. Writes `rawEmail` to `circom-zk-email/emls/api_input.eml`.
      2. Runs `scripts/generateWitness.ts` via `ts-node --transpile-only`.
      3. Runs `scripts/prove.ts` via `ts-node --transpile-only` (uses rapidsnark when `USE_RAPIDSNARK=1`).
      4. Reads proof artifacts from `circom-zk-email/proofs/proof.json` and `circom-zk-email/proofs/public.json`.
    - Response JSON: `{ proof: <proof.json>, publicSignals: <public.json> }`.

- Scripts to run the server:

```json
"scripts": {
  "dev:server": "ts-node --transpile-only server/index.ts",
  "start:server": "ts-node --transpile-only server/index.ts"
}
```

### Proof Artifact Layout

- Circom / prover side:
  - `circom-zk-email/proofs/proof.json`
  - `circom-zk-email/proofs/public.json`

- Contract test side:
  - `zk-email-verifier-contract/tests/proofs/proof.json`
  - `zk-email-verifier-contract/tests/proofs/public.json`

- Helper script to sync proofs for tests (in `circom-zk-email/package.json`):

```json
"copy-proofs-for-tests": "mkdir -p proofs && mkdir -p ../zk-email-verifier-contract/tests/proofs && cp proofs/proof.json ../zk-email-verifier-contract/tests/proofs/proof.json && cp proofs/public.json ../zk-email-verifier-contract/tests/proofs/public.json",
"cargo:test": "pnpm generate-vk-contract && pnpm copy-proofs-for-tests && cd ../zk-email-verifier-contract && cargo test"
```

### Docker Image

- Dockerfile: `circom-zk-email/Dockerfile`
- Key features:
  - Based on `node:22-bullseye`.
  - Installs system dependencies for rapidsnark and builds it from source.
  - Sets:

    ```dockerfile
    ENV RAPIDSNARK=/opt/rapidsnark/build/rapidsnark
    ENV USE_RAPIDSNARK=1
    ```

  - Copies both `circom-zk-email` and `zk-email-verifier-contract` into `/app`.
  - Runs `npm install` in `circom-zk-email`.
  - Exposes port `5588` and runs `npm run start:server`.

- Example build & run (from repo root):

```bash
# Pre-step on host: compile circuit and generate vk.rs if desired
just compile-circuits
just generate-vk-contract

# Build image
docker build -f circom-zk-email/Dockerfile -t zk-email-prover .

# Run container
docker run --rm -p 5588:5588 zk-email-prover
```

The remaining TODO items are incremental hardening and documentation; the core Express ZK prover and Dockerized rapidsnark setup are already in place.

