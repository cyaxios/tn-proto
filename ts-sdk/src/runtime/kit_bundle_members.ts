import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { Buffer } from "node:buffer";

const BTN_READER = /^.+?\.btn\.mykit(?:\.(?:revoked|previous)\..+)?$/;
const HIBE_READER = /^.+?\.hibe\.(?:mpk|idpath|sk)$/;
const BTN_FULL = /^.+?\.btn\.(?:mykit|state)(?:\.(?:revoked|previous)\..+)?$/;
const HIBE_FULL = /^.+?\.hibe\.(?:mpk|idpath|sk|msk)(?:\.(?:revoked|previous)\..+)?$/;
const JWE_FULL = /^.+?\.jwe\.(?:mykey|sender|recipients)(?:\.revoked\..+)?$/;

function isReaderMember(rel: string): boolean {
  return BTN_READER.test(rel) || HIBE_READER.test(rel);
}

function isFullMember(rel: string): boolean {
  if (
    [
      "local.private",
      "local.public",
      "index_master.key",
      "tn.yaml",
      "WARNING_CONTAINS_PRIVATE_KEYS",
    ].includes(rel)
  ) {
    return true;
  }
  return (
    BTN_FULL.test(rel) ||
    HIBE_FULL.test(rel) ||
    JWE_FULL.test(rel) ||
    /^.+?\.hibe\.idpath\.history$/.test(rel)
  );
}

export function kitBundleInstallRejection(opts: {
  kind: string;
  fromDid: string;
  toDid?: string;
  localDid: string;
  names: Iterable<string>;
}): string | null {
  const full = opts.kind === "full_keystore";
  if (full && (opts.fromDid !== opts.localDid || opts.toDid !== opts.localDid)) {
    return "full_keystore restore requires fromDid and toDid to both match this device";
  }
  for (const name of opts.names) {
    if (!name.startsWith("body/")) continue;
    const rel = name.slice("body/".length);
    const flat = rel.length > 0 && !rel.includes("/") && !rel.includes("\\");
    if (!flat || !(full ? isFullMember(rel) : isReaderMember(rel))) {
      const label = full ? "a full keystore" : "a reader kit";
      return `${opts.kind} member ${JSON.stringify(rel)} is not permitted in ${label}`;
    }
  }
  return null;
}

export function kitMemberIsSecret(rel: string): boolean {
  return (
    rel === "local.private" ||
    rel === "index_master.key" ||
    /\.btn\.(?:mykit|state)(?:\.|$)/.test(rel) ||
    /\.hibe\.(?:sk|msk)(?:\.|$)/.test(rel) ||
    /\.jwe\.(?:mykey|sender)(?:\.|$)/.test(rel)
  );
}

export function atomicWriteKitMember(dest: string, data: Uint8Array, secret: boolean): void {
  mkdirSync(dirname(dest), { recursive: true });
  const tmp = `${dest}.tmp.${process.pid}.${randomUUID()}`;
  try {
    writeFileSync(tmp, Buffer.from(data), secret ? { flag: "wx", mode: 0o600 } : { flag: "wx" });
    renameSync(tmp, dest);
  } finally {
    if (existsSync(tmp)) rmSync(tmp, { force: true });
  }
}
