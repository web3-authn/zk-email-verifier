#!/usr/bin/env bash
set -euo pipefail

# Run from `zk-email-verifier-contract/` (e.g. `./scripts/upgrade.sh`).
source .env

: "${CONTRACT_ID:?Missing CONTRACT_ID}"
: "${NEAR_NETWORK_ID:?Missing NEAR_NETWORK_ID}"
: "${DEPLOYER_PUBLIC_KEY:?Missing DEPLOYER_PUBLIC_KEY}"
: "${DEPLOYER_PRIVATE_KEY:?Missing DEPLOYER_PRIVATE_KEY}"

cargo near deploy build-reproducible-wasm "$CONTRACT_ID" \
  without-init-call \
  network-config "$NEAR_NETWORK_ID" \
  sign-with-plaintext-private-key \
  --signer-public-key "$DEPLOYER_PUBLIC_KEY" \
  --signer-private-key "$DEPLOYER_PRIVATE_KEY" \
  send
