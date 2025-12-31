default:
    @just --list

# Prover steps (run from repo root)

compile-circuits:
    cd circom-zk-email && pnpm compile-circuits

download-taus:
    cd circom-zk-email && pnpm download-taus

generate-witness:
    cd circom-zk-email && pnpm generate-witness

prove:
    cd circom-zk-email && pnpm prove

verify:
    cd circom-zk-email && pnpm verify


### Contract Side

generate-vk-contract:
    cd circom-zk-email && pnpm generate-vk-contract

cargo-build:
    cd circom-zk-email && pnpm generate-vk-contract
    cd zk-email-verifier-contract && cargo near build

cargo-test:
    cd circom-zk-email && pnpm generate-vk-contract && pnpm copy-proofs-for-tests
    cd zk-email-verifier-contract && cargo test -- --nocapture


### E2E Testing

# E2E test: Generate proof via Docker prover -> Verify on NEAR sandbox
# Requires: Docker prover running (just docker-run)
test-e2e:
    cd zk-email-verifier-contract && cargo test --test e2e_test -- --nocapture


### Dockerized ZK prover server

# Build the Docker image that bundles the Express prover server + rapidsnark
# (C++ only, no ffiasm). Pre-steps (recommended): `just compile-circuits` and
# `just generate-vk-contract` so the circuit artifacts and vk.rs are present
# in the build context.
docker-build:
    docker build -f circom-zk-email/Dockerfile -t zk-email-prover .

# Run the prover server container on localhost:5588.
docker-run:
    docker run --rm -p 5588:5588 zk-email-prover

# Assembly-enabled prover image (rapidsnark USE_ASM=ON) for native linux/amd64.
docker-build-asm:
    docker build --platform linux/amd64 -f circom-zk-email/Dockerfile.assembly -t zk-email-prover-asm .

docker-run-asm:
    docker run --rm --platform linux/amd64 -p 5588:5588 zk-email-prover-asm

# Test the prover endpoint (alias)
test-prove:
    cd circom-zk-email && pnpm test:prove
