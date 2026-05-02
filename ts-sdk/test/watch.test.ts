import { test } from "node:test";
import { strict as assert } from "node:assert";
import { renameSync, truncateSync, writeFileSync } from "node:fs";
import { Tn } from "../src/tn.js";

test("tn.watch yields new appends after subscribe (since='now', default)", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    const seen: string[] = [];
    const iter = tn.watch();
    const reader = (async () => {
      for await (const entry of iter) {
        seen.push(entry["event_type"] as string);
        if (seen.length >= 2) break;
      }
    })();

    // Give the watcher a tick to bind to the file.
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
        seen.push(entry["event_type"] as string);
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
        seen.push(e["event_type"] as string);
        if (seen.length >= 1) break;
      }
    })();

    // Wait for the watcher to bind, then rotate: rename current → .1,
    // create new empty file at the same path → new inode.
    await new Promise((r) => setTimeout(r, 150));
    renameSync(logPath, `${logPath}.1`);
    writeFileSync(logPath, "");
    await new Promise((r) => setTimeout(r, 150));
    tn.info("post-rotate", {});

    // Give the rotation drain a tick to land before timing out.
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
    // Emit the SAME event type 5 times so that `sequence` increments 1→5.
    // TN sequences are per-event-type, so identical event_type = monotonic counter.
    for (let i = 1; i <= 5; i++) tn.info("watch.test.seq", { i });
    // The third emit of watch.test.seq has sequence=3 in the envelope.
    // Confirm via the raw log.
    const allEntries = [...tn.read({ allRuns: true })].filter(
      (e) => e["event_type"] === "watch.test.seq",
    );
    assert.ok(allEntries.length >= 5, "expected 5 watch.test.seq entries; got " + allEntries.length);
    // Pass the sequence number of the third entry as the since cursor.
    const targetSeq = allEntries[2]!["sequence"] as number; // should be 3

    const seen: number[] = [];
    const iter = tn.watch({ since: targetSeq });
    const reader = (async () => {
      for await (const e of iter) {
        if (e["event_type"] !== "watch.test.seq") continue; // skip admin events
        seen.push(e["sequence"] as number);
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
    // Should yield sequences 3, 4, 5, 6 (seq.1 and seq.2 are skipped).
    assert.deepEqual(seen, [3, 4, 5, 6]);
  } finally {
    await tn.close();
  }
});

test("tn.watch with since=<ISO timestamp> resumes from a timestamp", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    tn.info("early", {});
    // Capture a cutoff timestamp strictly after the first entry's
    // timestamp. ISO-8601 lexicographic ordering matches chronological
    // ordering, so a millisecond gap is enough.
    await new Promise((r) => setTimeout(r, 10));
    const cutoff = new Date().toISOString();
    await new Promise((r) => setTimeout(r, 10));
    tn.info("late.1", {});
    tn.info("late.2", {});

    const seen: string[] = [];
    const iter = tn.watch({ since: cutoff });
    const reader = (async () => {
      for await (const e of iter) {
        seen.push(e["event_type"] as string);
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
        seen.push(e["event_type"] as string);
        // Collect until we see the post-truncate entry (the truncation admin
        // event may arrive in the same drain batch immediately before it).
        if (seen.includes("after-truncate")) break;
        // Safety cap to avoid hanging if something goes wrong.
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
    // The "after-truncate" entry must have been yielded.
    assert.ok(seen.includes("after-truncate"), `expected "after-truncate" in ${JSON.stringify(seen)}`);

    // The truncation event itself shows up in subsequent reads of the log,
    // emitted at warning level. Read all entries (allRuns: true to bypass
    // run_id filtering, since the warning is emitted by the watcher path).
    const all = [...tn.read({ allRuns: true })];
    const truncationLogged = all.some((e) => e["event_type"] === "tn.watch.truncation_observed");
    assert.equal(truncationLogged, true, "expected tn.watch.truncation_observed in the log");
  } finally {
    await tn.close();
  }
});
