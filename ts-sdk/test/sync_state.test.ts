// Tests for sync_state TS port (mirror of Python tn.sync_state).
//
// Spec ref §4.9 + §10 deferred workstream item 5 (cross-binding parity
// per item 16). The file format is identical to Python's so the same
// state.json file works for both.

import { strict as assert } from "node:assert";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  getInboxCursor,
  getLastPushedAdminHead,
  loadSyncState,
  saveSyncState,
  setInboxCursor,
  setLastPushedAdminHead,
  statePath,
  updateSyncState,
} from "../src/index.js";

function tmpYamlPath(): { yamlPath: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tn-sync-state-"));
  return {
    yamlPath: join(dir, "tn.yaml"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test("load returns empty when file missing", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    assert.deepEqual(loadSyncState(yamlPath), {});
  } finally {
    cleanup();
  }
});

test("save then load roundtrips", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    saveSyncState(yamlPath, { a: 1, b: "two", c: ["x", "y"] });
    assert.deepEqual(loadSyncState(yamlPath), { a: 1, b: "two", c: ["x", "y"] });
  } finally {
    cleanup();
  }
});

test("save creates parent directory", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    const sp = statePath(yamlPath);
    saveSyncState(yamlPath, { k: "v" });
    assert.ok(existsSync(sp));
  } finally {
    cleanup();
  }
});

test("update merges fields", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    saveSyncState(yamlPath, { a: 1, b: 2 });
    const newState = updateSyncState(yamlPath, { b: 20, c: 3 });
    assert.deepEqual(newState, { a: 1, b: 20, c: 3 });
    assert.deepEqual(loadSyncState(yamlPath), { a: 1, b: 20, c: 3 });
  } finally {
    cleanup();
  }
});

test("update with null clears field", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    saveSyncState(yamlPath, { a: 1, b: 2 });
    updateSyncState(yamlPath, { b: null });
    assert.deepEqual(loadSyncState(yamlPath), { a: 1 });
  } finally {
    cleanup();
  }
});

test("corrupt file treated as empty", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    const sp = statePath(yamlPath);
    // mkdir parent
    saveSyncState(yamlPath, { k: "v" }); // creates dir
    writeFileSync(sp, "{ this is not valid json", "utf8");
    assert.deepEqual(loadSyncState(yamlPath), {});
  } finally {
    cleanup();
  }
});

test("non-object root treated as empty", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    saveSyncState(yamlPath, { k: "v" });
    writeFileSync(statePath(yamlPath), '["not", "an", "object"]', "utf8");
    assert.deepEqual(loadSyncState(yamlPath), {});
  } finally {
    cleanup();
  }
});

test("typed helper getLastPushedAdminHead returns null when unset", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    assert.equal(getLastPushedAdminHead(yamlPath), null);
  } finally {
    cleanup();
  }
});

test("typed helper set then get", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    setLastPushedAdminHead(yamlPath, "sha256:abc123");
    assert.equal(getLastPushedAdminHead(yamlPath), "sha256:abc123");
    const state = loadSyncState(yamlPath);
    assert.equal(state["last_pushed_admin_head"], "sha256:abc123");
  } finally {
    cleanup();
  }
});

test("set preserves other fields", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    saveSyncState(yamlPath, {
      vault_endpoint: "https://example.com",
      inbox_cursor: "abc",
    });
    setLastPushedAdminHead(yamlPath, "sha256:xyz");
    assert.deepEqual(loadSyncState(yamlPath), {
      vault_endpoint: "https://example.com",
      inbox_cursor: "abc",
      last_pushed_admin_head: "sha256:xyz",
    });
  } finally {
    cleanup();
  }
});

test("non-string head value returns null from getter", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    saveSyncState(yamlPath, { last_pushed_admin_head: 42 });
    assert.equal(getLastPushedAdminHead(yamlPath), null);
  } finally {
    cleanup();
  }
});

test("inbox cursor typed helpers", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    assert.equal(getInboxCursor(yamlPath), null);
    setInboxCursor(yamlPath, "marker-001");
    assert.equal(getInboxCursor(yamlPath), "marker-001");
    setInboxCursor(yamlPath, "marker-002");
    assert.equal(getInboxCursor(yamlPath), "marker-002");
  } finally {
    cleanup();
  }
});

test("file format compatible with Python — sorted keys + 2-space indent", () => {
  // Cross-binding parity: a file written by TS must be readable
  // (and look identical to) one written by Python.
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    saveSyncState(yamlPath, { b: 2, a: 1 });
    const text = readFileSync(statePath(yamlPath), "utf8");
    assert.ok(text.includes('"a": 1'));
    assert.ok(text.includes('"b": 2'));
    assert.ok(text.indexOf('"a": 1') < text.indexOf('"b": 2'), "keys should be sorted");
  } finally {
    cleanup();
  }
});

test("run-kill-rerun: state survives 'process' restart", () => {
  const { yamlPath, cleanup } = tmpYamlPath();
  try {
    setLastPushedAdminHead(yamlPath, "sha256:run1-head");
    // Second "process": fresh start (in-process simulation), see
    // persisted value.
    assert.equal(getLastPushedAdminHead(yamlPath), "sha256:run1-head");
    setLastPushedAdminHead(yamlPath, "sha256:run2-head");
    assert.equal(getLastPushedAdminHead(yamlPath), "sha256:run2-head");
  } finally {
    cleanup();
  }
});
