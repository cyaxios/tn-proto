// Keystore on-disk layout (mirrors Python tn.logger + tn.cipher.BtnGroupCipher):
//
//   <keystore>/local.private        32-byte Ed25519 seed
//   <keystore>/local.public         UTF-8 did:key:... (diagnostic)
//   <keystore>/index_master.key     32-byte HMAC master for field tokens
//   <keystore>/<group>.btn.state    btn PublisherState bytes (SECRET)
//   <keystore>/<group>.btn.mykit    self-kit bytes so the publisher can read
//
// We do not touch jwe/bgw layouts here. A JWE ceremony yaml loaded
// through this module will still read the keystore parts that exist
// but cannot emit or read.

import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

import { DeviceKey } from "../signing.js";

export interface LoadedKeystore {
  device: DeviceKey;
  indexMaster: Uint8Array;
  // Per-group state. Keys are group names. Values carry the raw btn
  // publisher-state bytes plus any kit bytes we found on disk (current
  // self-kit plus any rotation-preserved kits).
  groups: Map<string, GroupKeystore>;
}

export interface GroupKeystore {
  stateBytes: Uint8Array;
  kits: Uint8Array[]; // index 0 is the current self-kit
}

export function loadKeystore(keystorePath: string): LoadedKeystore {
  const privatePath = join(keystorePath, "local.private");
  const indexPath = join(keystorePath, "index_master.key");

  const seed = new Uint8Array(readFileSync(privatePath));
  if (seed.length !== 32) {
    throw new Error(`local.private must be 32 bytes, got ${seed.length}`);
  }
  const device = DeviceKey.fromSeed(seed);

  const indexMaster = new Uint8Array(readFileSync(indexPath));
  if (indexMaster.length !== 32) {
    throw new Error(`index_master.key must be 32 bytes, got ${indexMaster.length}`);
  }

  const groups = new Map<string, GroupKeystore>();
  const groupNames = new Set<string>();
  for (const entry of readdirSync(keystorePath)) {
    const m = entry.match(/^(.+)\.btn\.state$/);
    if (m && m[1]) groupNames.add(m[1]);
  }
  for (const name of groupNames) {
    const stateBytes = new Uint8Array(readFileSync(join(keystorePath, `${name}.btn.state`)));
    const kits: Uint8Array[] = [];
    const selfKitPath = join(keystorePath, `${name}.btn.mykit`);
    if (existsSync(selfKitPath)) {
      kits.push(new Uint8Array(readFileSync(selfKitPath)));
    }
    // Rotation-preserved kits: `<group>.btn.mykit.revoked.<ts>`
    for (const entry of readdirSync(keystorePath)) {
      if (entry.startsWith(`${name}.btn.mykit.revoked.`)) {
        kits.push(new Uint8Array(readFileSync(join(keystorePath, entry))));
      }
    }
    groups.set(name, { stateBytes, kits });
  }

  return { device, indexMaster, groups };
}

/** Write (or overwrite) a group's btn state to the keystore. */
export function writeGroupState(keystorePath: string, groupName: string, state: Uint8Array): void {
  writeFileSync(join(keystorePath, `${groupName}.btn.state`), state);
}

/** Write a group's self-kit bytes. */
export function writeGroupMyKit(keystorePath: string, groupName: string, kit: Uint8Array): void {
  writeFileSync(join(keystorePath, `${groupName}.btn.mykit`), kit);
}
