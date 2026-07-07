import { strict as assert } from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { hibeKeyIdPath } from "../src/raw.js";
import {
  createHibeGroup,
  hibeDecrypt,
  hibeEncrypt,
  hibeMintReaderKey,
  hibeRotateIdPath,
  loadHibeGroup,
} from "../src/runtime/hibe_group.js";

test("hibe group names and identity paths reject ambiguous filesystem/path inputs", () => {
  const work = mkdtempSync(join(tmpdir(), "hibe-validation-"));
  const escaped = join(work, "..", "evil.hibe.mpk");
  try {
    assert.throws(() => createHibeGroup(work, "../evil"), /group name/i);
    assert.equal(existsSync(escaped), false, "unsafe group name wrote outside the keystore");

    const badPaths = [
      "",
      "team//reader",
      "/reader",
      "reader/",
      "team/../reader",
      "team/./reader",
      " team/reader",
      "team/reader ",
    ];
    for (const [i, idPath] of badPaths.entries()) {
      assert.throws(
        () => createHibeGroup(work, `g${i}`, { idPath }),
        /identity path/i,
        `accepted ${JSON.stringify(idPath)}`,
      );
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
    rmSync(join(work, "..", "evil.hibe.msk"), { force: true });
    rmSync(join(work, "..", "evil.hibe.sk"), { force: true });
    rmSync(join(work, "..", "evil.hibe.mpk"), { force: true });
    rmSync(join(work, "..", "evil.hibe.idpath"), { force: true });
  }
});

test("loadHibeGroup rejects persisted identity paths that trim to a different value", () => {
  const work = mkdtempSync(join(tmpdir(), "hibe-load-trim-"));
  try {
    createHibeGroup(work, "g", { idPath: "self" });
    writeFileSync(join(work, "g.hibe.idpath"), " self ", "utf8");

    assert.throws(() => loadHibeGroup(work, "g"), /identity path/i);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("hibe external-authority create writes only public sealing material", () => {
  const authorityDir = mkdtempSync(join(tmpdir(), "hibe-authority-"));
  const writerDir = mkdtempSync(join(tmpdir(), "hibe-writer-"));
  try {
    const authority = createHibeGroup(authorityDir, "auth", { idPath: "root" });
    const writer = createHibeGroup(writerDir, "orders", {
      authorityMpk: authority.mpk,
      idPath: "team",
    });

    assert.deepEqual(writer.mpk, authority.mpk);
    assert.equal(writer.msk, undefined, "external-authority writer must not mint an msk");
    assert.equal(writer.sk, undefined, "external-authority writer must not mint a reader sk");
    assert.equal(existsSync(join(writerDir, "orders.hibe.msk")), false);
    assert.equal(existsSync(join(writerDir, "orders.hibe.sk")), false);

    const blob = hibeEncrypt(writer, new TextEncoder().encode("governed"));
    assert.throws(() => hibeDecrypt(writer, blob), /no delegated identity key/i);

    const readerSk = hibeMintReaderKey(authority, "team");
    const opened = hibeDecrypt(
      { mpk: authority.mpk, idPath: "team", sk: readerSk, priorPaths: [], priorSks: [] },
      blob,
    );
    assert.equal(new TextDecoder().decode(opened), "governed");
  } finally {
    rmSync(authorityDir, { recursive: true, force: true });
    rmSync(writerDir, { recursive: true, force: true });
  }
});

test("hibe rotation stages old state before swapping active key and path", () => {
  const work = mkdtempSync(join(tmpdir(), "hibe-rotate-order-"));
  try {
    const mat = createHibeGroup(work, "g", { idPath: "self" });
    const historyPath = join(work, "g.hibe.idpath.history");
    mkdirSync(historyPath);

    assert.throws(() => hibeRotateIdPath(work, "g", mat, "next"));

    assert.equal(readFileSync(join(work, "g.hibe.idpath"), "utf8"), "self");
    assert.equal(
      hibeKeyIdPath(new Uint8Array(readFileSync(join(work, "g.hibe.sk")))),
      "self",
      "active identity key changed before history was staged",
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
