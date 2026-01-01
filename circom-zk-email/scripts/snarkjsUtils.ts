import fs from "fs";
import path from "path";
import { spawnSync, SpawnSyncOptions } from "child_process";

const DEFAULT_SNARKJS_MAX_OLD_SPACE_SIZE_MB = 8192;

export function getSnarkjsMaxOldSpaceSizeMb(): number {
  const raw = process.env.SNARKJS_MAX_OLD_SPACE_SIZE_MB;
  if (raw == null || raw.trim().length === 0) return DEFAULT_SNARKJS_MAX_OLD_SPACE_SIZE_MB;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 1024) return DEFAULT_SNARKJS_MAX_OLD_SPACE_SIZE_MB;
  return parsed;
}

export function runSnarkjs(args: string[], opts: SpawnSyncOptions = {}): void {
  const cliPath = path.join(
    __dirname,
    "..",
    "node_modules",
    "snarkjs",
    "build",
    "cli.cjs"
  );

  const needsHeapFlag =
    process.env.NODE_OPTIONS == null ||
    !process.env.NODE_OPTIONS.includes("--max-old-space-size");
  const nodeArgs = needsHeapFlag
    ? [`--max-old-space-size=${getSnarkjsMaxOldSpaceSizeMb()}`, cliPath, ...args]
    : [cliPath, ...args];

  const res = spawnSync("node", nodeArgs, {
    stdio: "inherit",
    ...opts,
  });

  if (res.status !== 0) {
    throw new Error(`snarkjs ${args.join(" ")} failed with exit code ${res.status}`);
  }
}

export function ensureFileExists(p: string, message?: string): void {
  if (!fs.existsSync(p)) {
    throw new Error(message || `Required file not found: ${p}`);
  }
}

export type ZkeyCheckResult = { ok: true } | { ok: false; reason: string };

export function checkGroth16ZkeyLayout(zkeyPath: string): ZkeyCheckResult {
  const REQUIRED_SECTIONS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  let fd: number | null = null;

  try {
    fd = fs.openSync(zkeyPath, "r");
    const stat = fs.fstatSync(fd);
    const fileSize = BigInt(stat.size);
    if (fileSize < 12n) {
      return { ok: false, reason: `file too small (${stat.size} bytes)` };
    }

    const fileHeader = Buffer.alloc(12);
    fs.readSync(fd, fileHeader, 0, 12, 0);
    const magic = fileHeader.toString("utf8", 0, 4);
    if (magic !== "zkey") {
      return { ok: false, reason: `bad magic (${JSON.stringify(magic)})` };
    }

    const version = fileHeader.readUInt32LE(4);
    if (version !== 1) {
      return { ok: false, reason: `unsupported version (${version})` };
    }

    const nSections = fileHeader.readUInt32LE(8);
    if (nSections !== 10) {
      return { ok: false, reason: `unexpected nSections (${nSections})` };
    }

    const seen = new Set<number>();
    let pos = 12n;
    const sectionHeader = Buffer.alloc(12);

    for (let i = 0; i < nSections; i++) {
      if (pos + 12n > fileSize) {
        return {
          ok: false,
          reason: `unexpected EOF reading section header #${i + 1} at offset ${pos.toString()}`,
        };
      }

      fs.readSync(fd, sectionHeader, 0, 12, Number(pos));
      const sectionType = sectionHeader.readUInt32LE(0);
      const sectionSize = sectionHeader.readBigUInt64LE(4);

      if (seen.has(sectionType)) {
        return { ok: false, reason: `duplicate section ${sectionType}` };
      }
      seen.add(sectionType);

      pos += 12n + sectionSize;
      if (pos > fileSize) {
        return {
          ok: false,
          reason: `section ${sectionType} exceeds file size (ends at ${pos.toString()}, file is ${fileSize.toString()})`,
        };
      }
    }

    if (pos !== fileSize) {
      return {
        ok: false,
        reason: `trailing bytes after last section (last ends at ${pos.toString()}, file is ${fileSize.toString()})`,
      };
    }

    for (const section of REQUIRED_SECTIONS) {
      if (!seen.has(section)) {
        return { ok: false, reason: `missing section ${section}` };
      }
    }

    return { ok: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `failed to parse zkey: ${msg}` };
  } finally {
    if (fd != null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
}

