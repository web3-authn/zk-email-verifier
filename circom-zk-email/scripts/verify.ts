#!/usr/bin/env node

/**
 * Verify a Groth16 proof for RecoverEmailCircuit using snarkjs.
 *
 * Usage:
 *   pnpm verify
 */

import path from "path";
import { ensureFileExists, runSnarkjs } from "./snarkjsUtils";

const SCRIPT_START = Date.now();

async function main(): Promise<void> {
  const repoRoot = path.join(__dirname, "..");
  const vkeyPath = path.join(repoRoot, "build", "verification_key.json");
  const proofsDir = path.join(repoRoot, "proofs");
  const proofPath = path.join(proofsDir, "proof.json");
  const publicPath = path.join(proofsDir, "public.json");

  ensureFileExists(
    vkeyPath,
    `Missing verification key at ${vkeyPath}. Generate it via:\n` +
      `  pnpm prove\n` +
      `or manually with snarkjs zkey export verificationkey.`
  );
  ensureFileExists(
    proofPath,
    `Missing proof at ${proofPath}. Generate it via:\n` +
      `  pnpm prove`
  );
  ensureFileExists(
    publicPath,
    `Missing public signals at ${publicPath}. Generate it via:\n` +
      `  pnpm prove`
  );

  console.log("Verifying proof...");
  runSnarkjs([
    "groth16",
    "verify",
    vkeyPath,
    publicPath,
    proofPath,
  ]);

  console.log("Proof verification OK");
  const elapsedMs = Date.now() - SCRIPT_START;
  console.log(`verify.ts completed in ${(elapsedMs / 1000).toFixed(2)}s`);
}

main().catch((err) => {
  console.error(err);
  const elapsedMs = Date.now() - SCRIPT_START;
  console.error(`verify.ts failed after ${(elapsedMs / 1000).toFixed(2)}s`);
  process.exit(1);
});
