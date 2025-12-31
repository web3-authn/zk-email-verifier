# zk-email

## Docker ZK Prover

Build:
```bash
just docker-build-prover
```

Run (exposes port 5588):
```bash
just docker-run-prover
```

Test endpoint:
```bash
just send-email-to-prover
```

## End-to-End Test

Full flow: Generate proof via Docker prover → Verify on NEAR sandbox

```bash
# Terminal 1: Start Docker prover
just docker-run-prover

# Terminal 2: Run e2e test (Rust integration test)
just test-e2e
```

The e2e test ([zk-email-verifier-contract/tests/e2e_test.rs](zk-email-verifier-contract/tests/e2e_test.rs)):
1. Calls `/prove-email` to generate a ZK proof
2. Saves proof to `zk-email-verifier-contract/tests/proofs/`
3. Deploys contract to NEAR sandbox
4. Verifies proof on-chain

### API Routes

**GET /healthz**
- Health check
- Returns: `{ "status": "ok" }`

**POST /prove-email**
- Generate ZK proof for email
- Body: `{ "rawEmail": "<email content>" }`
- Returns: `{ "proof": [...], "publicSignals": [...] }`
