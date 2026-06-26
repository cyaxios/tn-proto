import { test } from "node:test";
import { strict as assert } from "node:assert";
import { renameSync, truncateSync, writeFileSync } from "node:fs";
import { Tn } from "../src/tn.js";
import { Entry } from "../src/Entry.js";

function eventType(entry: Entry | Record<string, unknown>): string {
  return entry instanceof Entry
    ? entry.event_type
    : (entry["event_type"] as string);
}

function sequence(entry: Entry | Record<string, unknown>): number {
  return entry instanceof Entry ? entry.sequence : (entry["sequence"] as number);
}

test("tn.watch yields new appends after subscribe (since='now', default)", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const seen: string[] = [];
    const iter = tn.watch();
    const reader = (async () => {
      for await (const entry of iter) {
        seen.push(eventType(entry));
        if (seen.length >= 2) break;
      }
    })();

    await new Promise((r) => setTimeout(r, 150));
    tn.info("a", {});
    tn.info("b", {});

    await reader;
    assert.deepEqual(seen, ["a", "b"]);
  } finally {
    await tn.close();
  }
});

test("tn.watch with since='start' replays existing entries first", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    tn.info("pre.1", {});
    tn.info("pre.2", {});
    const seen: string[] = [];
    const iter = tn.watch({ since: "start" });
    const reader = (async () => {
      for await (const entry of iter) {
        seen.push(eventType(entry));
        if (seen.length >= 3) break;
      }
    })();
    await new Promise((r) => setTimeout(r, 150));
    tn.info("post.1", {});
    await reader;
    assert.deepEqual(seen, ["pre.1", "pre.2", "post.1"]);
  } finally {
    await tn.close();
  }
});

test("tn.watch handles file rotation (inode change)", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    tn.info("pre-rotate", {});
    const logPath = tn.logPath;
    const seen: string[] = [];
    const iter = tn.watch({ since: "now" });
    const reader = (async () => {
      for await (const e of iter) {
        seen.push(eventType(e));
        if (seen.length >= 1) break;
      }
    })();

    await new Promise((r) => setTimeout(r, 150));
    renameSync(logPath, `${logPath}.1`);
    writeFileSync(logPath, "");
    await new Promise((r) => setTimeout(r, 150));
    tn.info("post-rotate", {});

    await Promise.race([
      reader,
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error("timeout waiting for post-rotate entry")), 5000),
      ),
    ]);
    assert.equal(seen[0], "post-rotate");
  } finally {
    await tn.close();
  }
});

test("tn.watch with since=<sequence> resumes from the given seq", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    for (let i = 1; i <= 5; i++) tn.info("watch.test.seq", { i });
    const allEntries: Entry[] = [];
    for (const e of tn.read({ allRuns: true })) {
      if (e instanceof Entry && e.event_type === "watch.test.seq") allEntries.push(e);
    }
    assert.ok(allEntries.length >= 5, "expected 5 watch.test.seq entries; got " + allEntries.length);
    const targetSeq = allEntries[2]!.sequence;

    const seen: number[] = [];
    const iter = tn.watch({ since: targetSeq });
    const reader = (async () => {
      for await (const e of iter) {
        if (eventType(e) !== "watch.test.seq") continue;
        seen.push(sequence(e));
        if (seen.length >= 4) break;
      }
    })();
    await new Promise((r) => setTimeout(r, 150));
    tn.info("watch.test.seq", { i: 6 });

    await Promise.race([
      reader,
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error("timeout waiting for seq tail")), 5000),
      ),
    ]);
    assert.deepEqual(seen, [3, 4, 5, 6]);
  } finally {
    await tn.close();
  }
});

test("tn.watch with since=<ISO timestamp> resumes from a timestamp", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    tn.info("early", {});
    await new Promise((r) => setTimeout(r, 10));
    const cutoff = new Date().toISOString();
    await new Promise((r) => setTimeout(r, 10));
    tn.info("late.1", {});
    tn.info("late.2", {});

    const seen: string[] = [];
    const iter = tn.watch({ since: cutoff });
    const reader = (async () => {
      for await (const e of iter) {
        seen.push(eventType(e));
        if (seen.length >= 2) break;
      }
    })();

    await Promise.race([
      reader,
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error("timeout waiting for cutoff tail")), 5000),
      ),
    ]);
    assert.deepEqual(seen, ["late.1", "late.2"]);
  } finally {
    await tn.close();
  }
});

test("tn.watch on truncation emits tn.watch.truncation_observed and resumes from new end", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    tn.info("a", {});
    tn.info("b", {});
    const logPath = tn.logPath;

    const iter = tn.watch({ since: "now" });
    const seen: string[] = [];
    const reader = (async () => {
      for await (const e of iter) {
        seen.push(eventType(e));
        if (seen.includes("after-truncate")) break;
        if (seen.length >= 5) break;
      }
    })();

    await new Promise((r) => setTimeout(r, 150));
    truncateSync(logPath, 0);
    await new Promise((r) => setTimeout(r, 150));
    tn.info("after-truncate", {});

    await Promise.race([
      reader,
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error("timeout waiting for post-truncate entry")), 5000),
      ),
    ]);
    assert.ok(seen.includes("after-truncate"), `expected "after-truncate" in ${JSON.stringify(seen)}`);

    const all: Array<Entry | Record<string, unknown>> = [];
    for (const e of tn.read({ allRuns: true })) all.push(e);
    const truncationLogged = all.some((e) => eventType(e) === "tn.watch.truncation_observed");
    assert.equal(truncationLogged, true, "expected tn.watch.truncation_observed in the log");
  } finally {
    await tn.close();
  }
});
