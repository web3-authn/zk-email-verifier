#!/usr/bin/env node

import express from "express";
import { promises as fs } from "fs";
import path from "path";
import { spawn } from "child_process";

const PORT = process.env.PORT || 5588;
const CIRCOM_ROOT = path.join(__dirname, "..");

function run(
  cmd: string,
  args: string[],
  opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: { ...process.env, ...opts.env },
      stdio: "inherit",
    });
    child.on("error", (err) => reject(err));
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${cmd} ${args.join(" ")} exited with code ${code}`));
    });
  });
}

async function proveEmail(rawEmail: string): Promise<{
  proof: unknown;
  publicSignals: unknown;
}> {
  const emlPath = path.join(CIRCOM_ROOT, "emls", "api_input.eml");
  await fs.writeFile(emlPath, rawEmail, "utf8");

  // 1. Generate witness
  await run(
    "npx",
    ["ts-node", "--transpile-only", "scripts/generateWitness.ts", emlPath],
    { cwd: CIRCOM_ROOT }
  );

  // 2. Prove (will use rapidsnark if USE_RAPIDSNARK=1 and RAPIDSNARK set)
  await run(
    "npx",
    ["ts-node", "--transpile-only", "scripts/prove.ts", "powersOfTau28_hez_final_22.ptau"],
    { cwd: CIRCOM_ROOT }
  );

  // 3. Read proof artifacts from circom proofs directory
  const proofsDir = path.join(CIRCOM_ROOT, "proofs");
  const proofJson = await fs.readFile(path.join(proofsDir, "proof.json"), "utf8");
  const publicJson = await fs.readFile(path.join(proofsDir, "public.json"), "utf8");

  return {
    proof: JSON.parse(proofJson),
    publicSignals: JSON.parse(publicJson),
  };
}

async function main(): Promise<void> {
  const app = express();
  app.use(express.json({ limit: "256kb" }));

  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.post("/prove-email", async (req, res) => {
    const { rawEmail } = req.body ?? {};
    if (typeof rawEmail !== "string" || rawEmail.length === 0) {
      res.status(400).json({ error: "rawEmail (string) is required" });
      return;
    }

    try {
      const { proof, publicSignals } = await proveEmail(rawEmail);
      res.json({ proof, publicSignals });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("prove-email failed:", err);
      res.status(500).json({ error: "proving_failed" });
    }
  });

  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`ZK prover server listening on port ${PORT}`);
  });
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("server failed to start:", err);
  process.exit(1);
});

