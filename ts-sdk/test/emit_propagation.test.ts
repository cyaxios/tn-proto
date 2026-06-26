/**
 * Live emit on multi-ceremony streams + handler propagation.
 *
 * Mirrors python/tests/test_emit_propagation.py. Verifies that
 * ``Tn.use(name).info(...)`` writes attested entries to the named
 * stream's log, identity is shared from the Project root, and per-emit
 * dedup keeps duplicate addresses from double-writing.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { Tn } from "../src/tn.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "tn-emit-prop-"));
}

function projectName(projectDir: string): string {
  return projectDir.split(/[\\/]/).pop() ?? "";
}

test("use(default) auto-creates the Project and emits land in its log", async () => {
  const td = tmp();
  try {
    const orig = process.env.TN_NO_STDOUT;
    process.env.TN_NO_STDOUT = "1";
    try {
      const tn = await Tn.use("default", {
        project: projectName(td),
        projectDir: td,
      });
      try {
        tn.info("evt.test", { k: 1 });
      } finally {
        await tn.close();
      }
    } finally {
      if (orig === undefined) delete process.env.TN_NO_STDOUT;
      else process.env.TN_NO_STDOUT = orig;
    }
    // Default's log file exists with our event.
    const logPath = join(td, ".tn", projectName(td), "logs", "default.ndjson");
    assert.ok(existsSync(logPath), `expected log at ${logPath}`);
    const text = readFileSync(logPath, "utf8");
    assert.match(text, /evt\.test/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("named stream auto-create + emit: writes to stream's own log", async () => {
  const td = tmp();
  try {
    const orig = process.env.TN_NO_STDOUT;
    process.env.TN_NO_STDOUT = "1";
    try {
      const tn = await Tn.use("payments", {
        projectDir: td,
        profile: "transaction",
      });
      try {
        tn.info("payment.charged", { amount: 4999 });
      } finally {
        await tn.close();
      }
    } finally {
      if (orig === undefined) delete process.env.TN_NO_STDOUT;
      else process.env.TN_NO_STDOUT = orig;
    }
    // Payments has its own log file.
    const logPath = join(td, ".tn", projectName(td), "logs", "payments.ndjson");
    assert.ok(existsSync(logPath), `expected log at ${logPath}`);
    const text = readFileSync(logPath, "utf8");
    assert.match(text, /payment\.charged/);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("two streams in one project share device DID", async () => {
  const td = tmp();
  try {
    const orig = process.env.TN_NO_STDOUT;
    process.env.TN_NO_STDOUT = "1";
    let aDid = "";
    let bDid = "";
    try {
      const a = await Tn.use("a", { projectDir: td });
      try {
        aDid = a.did;
      } finally {
        await a.close();
      }
      const b = await Tn.use("b", {
        projectDir: td,
        profile: "audit",
      });
      try {
        bDid = b.did;
      } finally {
        await b.close();
      }
    } finally {
      if (orig === undefined) delete process.env.TN_NO_STDOUT;
      else process.env.TN_NO_STDOUT = orig;
    }
    // Both streams resolve the same device DID via shared identity.
    assert.equal(aDid, bDid);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("two streams' events do not cross-contaminate", async () => {
  const td = tmp();
  try {
    const orig = process.env.TN_NO_STDOUT;
    process.env.TN_NO_STDOUT = "1";
    try {
      const a = await Tn.use("a", { projectDir: td });
      try {
        a.info("a.event", { value: 1 });
      } finally {
        await a.close();
      }
      const b = await Tn.use("b", {
        projectDir: td,
        profile: "audit",
      });
      try {
        b.info("b.event", { value: 2 });
      } finally {
        await b.close();
      }
    } finally {
      if (orig === undefined) delete process.env.TN_NO_STDOUT;
      else process.env.TN_NO_STDOUT = orig;
    }
    const root = join(td, ".tn", projectName(td));
    const aLog = readFileSync(join(root, "logs", "a.ndjson"), "utf8");
    const bLog = readFileSync(join(root, "logs", "b.ndjson"), "utf8");
    assert.match(aLog, /a\.event/);
    assert.match(bLog, /b\.event/);
    assert.equal(aLog.includes("b.event"), false);
    assert.equal(bLog.includes("a.event"), false);
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});

test("each profile produces its expected default sink in stream yaml", async () => {
  const td = tmp();
  try {
    const orig = process.env.TN_NO_STDOUT;
    process.env.TN_NO_STDOUT = "1";
    try {
      // transaction = file_rotating
      const a = await Tn.use("a", {
        projectDir: td,
        profile: "transaction",
      });
      await a.close();
      const aYaml = readFileSync(join(td, ".tn", projectName(td), "streams", "a.yaml"), "utf8");
      assert.match(aYaml, /kind: file\.rotating/);

      // telemetry = stdout
      const b = await Tn.use("b", {
        projectDir: td,
        profile: "telemetry",
      });
      await b.close();
      const bYaml = readFileSync(join(td, ".tn", projectName(td), "streams", "b.yaml"), "utf8");
      assert.match(bYaml, /kind: stdout/);
    } finally {
      if (orig === undefined) delete process.env.TN_NO_STDOUT;
      else process.env.TN_NO_STDOUT = orig;
    }
  } finally {
    rmSync(td, { recursive: true, force: true });
  }
});
