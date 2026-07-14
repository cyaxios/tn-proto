import { existsSync, readdirSync } from "node:fs";

const KEY_SUFFIXES = [
  /^(.*)\.btn\.mykit(?:\.(?:retired|revoked)\..+)?$/,
  /^(.*)\.hibe\.sk(?:\.previous\..+)?$/,
  /^(.*)\.jwe\.mykey(?:\.revoked\..+)?$/,
];

/** Discover every group for which this keystore carries reader material. */
export function discoverRecipientGroups(keystorePath: string): string[] {
  if (!existsSync(keystorePath)) return [];
  const groups = new Set<string>();
  for (const name of readdirSync(keystorePath)) {
    for (const pattern of KEY_SUFFIXES) {
      const match = pattern.exec(name);
      if (match?.[1]) groups.add(match[1]);
    }
  }
  return [...groups].sort();
}
