#!/usr/bin/env node

/**
 * Verify a Groth16 proof for RecoverEmailCircuit using snarkjs.
 *
 * Usage:
 *   pnpm verify
 */

import fs from "fs";
import path from "path";
import { spawnSync, SpawnSyncOptions } from "child_process";

const SCRIPT_START = Date.now();

function ensureFileExists(p: string, message?: string): void {
  if (!fs.existsSync(p)) {
    throw new Error(message || `Required file not found: ${p}`);
  }
}

function runSnarkjs(args: string[], opts: SpawnSyncOptions = {}): void {
  const cliPath = path.join(
    __dirname,
    "..",
    "node_modules",
    "snarkjs",
    "build",
    "cli.cjs"
  );

  const res = spawnSync("node", [cliPath, ...args], {
    stdio: "inherit",
    ...opts,
  });

  if (res.status !== 0) {
    throw new Error(`snarkjs ${args.join(" ")} failed with exit code ${res.status}`);
  }
}

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
