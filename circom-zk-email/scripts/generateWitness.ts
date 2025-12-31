#!/usr/bin/env node

/**
 * Generate inputs for RecoverEmailCircuit and compute the witness.
 *
 * Usage:
 *   pnpm generate-witness
 *
 * Outputs:
 *   ./input.json
 *   ./witness.wtns
 */

import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";
import dns from "dns";

const SCRIPT_START = Date.now();

// dns.promises isn't typed in older node typings without dom; wrap manually.
const dnsPromises = (dns as unknown as { promises: typeof dns.promises }).promises;

// eslint-disable-next-line @typescript-eslint/no-var-requires
const {
  generateEmailVerifierInputs,
  MAX_BODY_PADDED_BYTES,
} = require("@zk-email/helpers") as {
  generateEmailVerifierInputs: (raw: Buffer, opts: {
    ignoreBodyHashCheck: boolean;
    maxHeadersLength: number;
    maxBodyLength: number;
  }) => Promise<{
    emailHeader: unknown[];
    emailHeaderLength: string | number;
    pubkey: unknown[];
    signature: unknown[];
  }>;
  MAX_BODY_PADDED_BYTES: number;
};

async function main(): Promise<void> {
  const emlPath =
    process.argv[2] || path.join(__dirname, "..", "emls", "test.eml");

  if (!fs.existsSync(emlPath)) {
    throw new Error(
      `EML file not found at ${emlPath}. Pass a path explicitly, e.g.:\n` +
        `  pnpm generate-witness`
    );
  }

  console.log(`Reading email from: ${emlPath}`);
  const rawEmail = fs.readFileSync(emlPath);

  // Quick DNS sanity check for Gmail's DKIM key
  try {
    console.log(
      "Testing DNS TXT lookup for 20230601._domainkey.gmail.com..."
    );
    const txt = await dnsPromises.resolveTxt("20230601._domainkey.gmail.com");
    console.log("DNS TXT records:", txt);
  } catch (e) {
    console.error("DNS TXT lookup failed:", e);
  }

  console.log("Generating EmailVerifier inputs via @zk-email/helpers...");
  const emailVerifierInputs = await generateEmailVerifierInputs(rawEmail, {
    ignoreBodyHashCheck: true,
    maxHeadersLength: 1024,
    maxBodyLength: MAX_BODY_PADDED_BYTES,
  });

  // Build a header string so we can locate
  // the start indices of the captures in bytes.
  const headerBytes = emailVerifierInputs.emailHeader.map((v: unknown) =>
    Number(v)
  );
  const headerLen = Number(emailVerifierInputs.emailHeaderLength);
  const headerBuf = Buffer.from(headerBytes.slice(0, headerLen));
  const headerStr = headerBuf.toString("utf8");

  console.log("Locating subject layout in header...");

  // Subject (new format, required):
  //   recover-<requestId> <accountId> ed25519:<pk>
  const subjectRegex =
    /subject:\s*recover-([^\s\r\n]+)\s+([^\s\r\n]+)\s+ed25519:([^\s\r\n]+)/i;
  const subjectMatch = subjectRegex.exec(headerStr);
  if (!subjectMatch) {
    throw new Error(
      'Failed to find "Subject: recover-<requestId> <accountId> ed25519:<pk>" pattern in the email header'
    );
  }

  const requestIdStr = subjectMatch[1];
  const accountIdStr = subjectMatch[2];
  const newPublicKeyStr = subjectMatch[3];

  const subjectFull = subjectMatch[0];
  const subjectBaseIndex = subjectMatch.index;

  const subject_start_idx = subjectBaseIndex;

  const requestIdOffset = subjectFull.indexOf(requestIdStr);
  if (requestIdOffset < 0) {
    throw new Error("Failed to locate request_id substring offset in Subject");
  }
  const subject_request_id_idx = subjectBaseIndex + requestIdOffset;
  const subject_request_id_len = Buffer.from(requestIdStr, "utf8").length;

  const accountIdOffset = subjectFull.indexOf(accountIdStr);
  if (accountIdOffset < 0) {
    throw new Error("Failed to locate account_id substring offset in Subject");
  }
  const subject_account_id_idx = subjectBaseIndex + accountIdOffset;

  const pkOffset = subjectFull.indexOf(newPublicKeyStr);
  if (pkOffset < 0) {
    throw new Error("Failed to locate new_public_key substring offset in Subject");
  }
  const subject_public_key_idx = subjectBaseIndex + pkOffset;

  const subject_account_id_len = Buffer.from(accountIdStr, "utf8").length;
  const subject_public_key_len = Buffer.from(newPublicKeyStr, "utf8").length;

  console.log("subject_start_idx:", subject_start_idx);
  console.log("subject_account_id_idx:", subject_account_id_idx);
  console.log("subject_public_key_idx:", subject_public_key_idx);

  console.log("Locating From: layout in header...");
  const fromLineRegex = /^from:[^\r\n]*$/im;
  const fromLineMatch = fromLineRegex.exec(headerStr);
  if (!fromLineMatch) {
    throw new Error('Failed to find "From:" header line in the email header');
  }
  const fromLine = fromLineMatch[0];
  const from_start_idx = fromLineMatch.index;

  // Prefer the email address inside angle brackets.
  let fromEmailStr: string;
  const angleMatch = /<([^>\s]+)>/.exec(fromLine);
  if (angleMatch) {
    fromEmailStr = angleMatch[1];
  } else {
    const bareMatch = /^from:\s*([^\s\r\n]+)/i.exec(fromLine);
    if (!bareMatch) {
      throw new Error('Failed to extract sender email from "From:" header');
    }
    fromEmailStr = bareMatch[1];
  }

  const fromEmailOffset = fromLine.indexOf(fromEmailStr);
  if (fromEmailOffset < 0) {
    throw new Error('Failed to locate sender email substring offset in "From:" header');
  }
  const from_addr_idx = from_start_idx + fromEmailOffset;
  const from_addr_len = Buffer.from(fromEmailStr, "utf8").length;

  console.log("from_start_idx:", from_start_idx);
  console.log("from_addr_idx:", from_addr_idx);

  console.log("Locating Date: timestamp in header...");
  const dateRegex = /^date:\s*([^\r\n]+)$/im;
  const dateMatch = dateRegex.exec(headerStr);
  if (!dateMatch) {
    throw new Error('Failed to find "Date:" header line in the email header');
  }
  const dateFull = dateMatch[0];
  const timestampStr = dateMatch[1];
  const date_start_idx = dateMatch.index;

  const tsOffset = dateFull.indexOf(timestampStr);
  if (tsOffset < 0) {
    throw new Error("Failed to locate timestamp substring offset in Date header");
  }
  const date_timestamp_idx = date_start_idx + tsOffset;
  const date_timestamp_len = Buffer.from(timestampStr, "utf8").length;

  console.log("date_start_idx:", date_start_idx);
  console.log("date_timestamp_idx:", date_timestamp_idx);

  // Assemble full RecoverEmailCircuit input.
  const circuitInput = {
    emailHeader: emailVerifierInputs.emailHeader,
    emailHeaderLength: emailVerifierInputs.emailHeaderLength,
    pubkey: emailVerifierInputs.pubkey,
    signature: emailVerifierInputs.signature,

    // Subject layout (private)
    subject_start_idx: subject_start_idx.toString(),
    subject_request_id_idx: subject_request_id_idx.toString(),
    subject_request_id_len: subject_request_id_len.toString(),
    subject_account_id_idx: subject_account_id_idx.toString(),
    subject_public_key_idx: subject_public_key_idx.toString(),
    subject_account_id_len: subject_account_id_len.toString(),
    subject_public_key_len: subject_public_key_len.toString(),

    // From: layout (private)
    from_start_idx: from_start_idx.toString(),
    from_addr_idx: from_addr_idx.toString(),
    from_addr_len: from_addr_len.toString(),

    // Date layout (private)
    date_start_idx: date_start_idx.toString(),
    date_timestamp_idx: date_timestamp_idx.toString(),
    date_timestamp_len: date_timestamp_len.toString(),
  };

  const inputPath = path.join(__dirname, "..", "input.json");
  fs.writeFileSync(inputPath, JSON.stringify(circuitInput, null, 2), "utf8");
  console.log(`Wrote circuit input to ${inputPath}`);

  const wasmPath = path.join(
    __dirname,
    "..",
    "build",
    "RecoverEmailCircuit_js",
    "RecoverEmailCircuit.wasm"
  );
  const witnessPath = path.join(__dirname, "..", "witness.wtns");
  const generatorPath = path.join(
    __dirname,
    "..",
    "build",
    "RecoverEmailCircuit_js",
    "generate_witness.js"
  );

  console.log("Computing witness with generate_witness.js...");
  const res = spawnSync(
    "node",
    [generatorPath, wasmPath, inputPath, witnessPath],
    { stdio: "inherit" }
  );

  if (res.status !== 0) {
    throw new Error(`generate_witness.js failed with exit code ${res.status}`);
  }

  console.log(`Witness written to ${witnessPath}`);

  const elapsedMs = Date.now() - SCRIPT_START;
  console.log(`generateWitness.ts completed in ${(elapsedMs / 1000).toFixed(2)}s`);
}

main().catch((err) => {
  console.error(err);
  const elapsedMs = Date.now() - SCRIPT_START;
  console.error(`generateWitness.ts failed after ${(elapsedMs / 1000).toFixed(2)}s`);
  process.exit(1);
});
