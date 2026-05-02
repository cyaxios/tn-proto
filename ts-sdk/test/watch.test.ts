import { test } from "node:test";
import { strict as assert } from "node:assert";
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
