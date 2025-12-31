#!/usr/bin/env node

/**
 * Prove RecoverEmailCircuit using snarkjs (Groth16).
 *
 * This script:
 *   1. Ensures a zkey and verification key exist (runs groth16 setup if needed).
 *   2. Generates proof.json and public.json from witness.wtns.
 */

import fs from "fs";
import path from "path";
import { spawnSync, SpawnSyncOptions } from "child_process";

const SCRIPT_START = Date.now();

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

function runRapidsnark(
  zkeyPath: string,
  witnessPath: string,
  proofPath: string,
  publicPath: string
): void {
  const bin = process.env.RAPIDSNARK || "rapidsnark";

  const res = spawnSync(bin, [zkeyPath, witnessPath, proofPath, publicPath], {
    stdio: "inherit",
  });

  if (res.error) {
    throw new Error(
      `Failed to run ${bin}: ${res.error.message}. Make sure rapidsnark is installed and RAPIDSNARK points to the binary if needed.`
    );
  }

  if (res.status !== 0) {
    const signalInfo =
      res.signal != null ? ` (signal: ${res.signal})` : "";
    throw new Error(
      `rapidsnark ${zkeyPath} ${witnessPath} ${proofPath} ${publicPath} failed with exit code ${res.status}${signalInfo}`
    );
  }
}

function ensureFileExists(p: string, message?: string): void {
  if (!fs.existsSync(p)) {
    throw new Error(message || `Required file not found: ${p}`);
  }
}

async function main(): Promise<void> {
  const repoRoot = path.join(__dirname, "..");
  const r1csPath = path.join(repoRoot, "build", "RecoverEmailCircuit.r1cs");
  const witnessPath = path.join(repoRoot, "witness.wtns");
  const defaultPtauPath = path.join(
    repoRoot,
    "powersOfTau28_hez_final_22.ptau"
  );
  const ptauPath = process.argv[2] || defaultPtauPath;

  const zkeyPath = path.join(repoRoot, "build", "RecoverEmailCircuit.zkey");
  const vkeyPath = path.join(repoRoot, "build", "verification_key.json");
  const proofsDir = path.join(repoRoot, "proofs");
  if (!fs.existsSync(proofsDir)) {
    fs.mkdirSync(proofsDir, { recursive: true });
  }
  const proofPath = path.join(proofsDir, "proof.json");
  const publicPath = path.join(proofsDir, "public.json");

  ensureFileExists(
    r1csPath,
    `Missing R1CS at ${r1csPath}. Compile the circuit first:\n` +
      `  pnpm compile-circuits`
  );

  ensureFileExists(
    witnessPath,
    `Missing witness at ${witnessPath}. Generate it first, e.g.:\n` +
      `  pnpm generate-witness`
  );

  ensureFileExists(
    ptauPath,
    `Missing Powers of Tau file at ${ptauPath}.\n` +
      `Download it, for example:\n` +
      `  pnpm download-taus\n` +
      `and place it at the repo root or pass the path as an argument.`
  );

  // 1) Setup (if needed): generate zkey and verification key
  if (!fs.existsSync(zkeyPath)) {
    console.log("No zkey found. Running groth16 setup...");
    runSnarkjs([
      "groth16",
      "setup",
      r1csPath,
      ptauPath,
      zkeyPath,
    ]);
  } else {
    console.log(`Using existing zkey: ${zkeyPath}`);
  }

  if (!fs.existsSync(vkeyPath)) {
    console.log("Exporting verification key...");
    runSnarkjs([
      "zkey",
      "export",
      "verificationkey",
      zkeyPath,
      vkeyPath,
    ]);
  } else {
    console.log(`Using existing verification key: ${vkeyPath}`);
  }

  // 2) Prove
  console.log("Generating proof (proof.json, public.json)...");
  if (process.env.USE_RAPIDSNARK === "1") {
    console.log("Using rapidsnark prover (USE_RAPIDSNARK=1)...");
    runRapidsnark(zkeyPath, witnessPath, proofPath, publicPath);
  } else {
    runSnarkjs([
      "groth16",
      "prove",
      zkeyPath,
      witnessPath,
      proofPath,
      publicPath,
    ]);
  }

  console.log(`Proof written to ${proofPath}`);
  console.log(`Public signals written to ${publicPath}`);

  const elapsedMs = Date.now() - SCRIPT_START;
  console.log(`prove.ts completed in ${(elapsedMs / 1000).toFixed(2)}s`);
}

main().catch((err) => {
  console.error(err);
  const elapsedMs = Date.now() - SCRIPT_START;
  console.error(`prove.ts failed after ${(elapsedMs / 1000).toFixed(2)}s`);
  process.exit(1);
});
