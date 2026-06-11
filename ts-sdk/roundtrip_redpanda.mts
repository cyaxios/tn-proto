// Full log+read round-trip for the TS Kafka handler against Redpanda Cloud.
// Companion to samples/redpanda-firehose/roundtrip_py.py.
//
// write: real Tn.info() -> KafkaHandler (registry/programmatic) -> Redpanda
// read:  KafkaHandler.reader() -> raw sealed bytes back from the broker
//
// Confirms the EXACT event_id produced by the real TS seal path comes back
// through the handler's OWN reader() (not a hand-rolled consumer).
//
//   cd ts-sdk
//   npm install --no-save kafkajs
//   RP_USERNAME=tn-firehose RP_PASSWORD=... KAFKAJS_NO_PARTITIONER_WARNING=1 \
//     node --import tsx ./roundtrip_redpanda.mts

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "./src/tn.js";
import { KafkaHandler } from "./src/handlers/kafka.js";

const BOOTSTRAP = "d8guu3lvi6v3jq8i6k2g.any.us-east-1.mpx.prd.cloud.redpanda.com:9092";
const TOPIC = "tn.firehose.00000000-0000-0000-0000-000000000001";
const USER = process.env["RP_USERNAME"] ?? "";
const PASS = process.env["RP_PASSWORD"] ?? "";

async function main(): Promise<number> {
  if (!USER || !PASS) {
    console.error("set RP_USERNAME and RP_PASSWORD");
    return 2;
  }
  process.env["TN_NO_STDOUT"] = "1";

  const projectDir = mkdtempSync(join(tmpdir(), "tn-rt-ts-"));
  const marker = "RTTS-" + Math.random().toString(16).slice(2, 14);

  // Kafka handler attached to the real ceremony's fan-out.
  const writeHandler = new KafkaHandler("rp", {
    outboxDir: join(projectDir, "outbox"),
    bootstrap: BOOTSTRAP,
    topic: TOPIC,
    sasl: { mechanism: "SCRAM-SHA-256", user: USER, pass: PASS },
    compressionType: "gzip",
    acks: "all",
  });
  await writeHandler.whenReady();

  // ── WRITE via the real TS SDK seal path ──────────────────────────
  const tn = await Tn.openCeremony("default", { projectDir, profile: "telemetry" });
  tn.handlers.add(writeHandler);
  const receipt = tn.info("roundtrip.ts", { marker });
  const wantId = receipt.eventId;
  console.log(`WROTE event_id=${wantId} marker=${marker}`);
  await tn.close(); // drains the kafka outbox

  // ── READ via the handler's own reader() ──────────────────────────
  const readHandler = new KafkaHandler("rp-reader", {
    outboxDir: join(projectDir, "outbox-reader"),
    bootstrap: BOOTSTRAP,
    topic: TOPIC,
    sasl: { mechanism: "SCRAM-SHA-256", user: USER, pass: PASS },
  });
  console.log(`reader source: ${readHandler.resolved_address()}`);

  let found: Record<string, unknown> | null = null;
  let scanned = 0;
  const deadline = Date.now() + 180_000;
  const it = readHandler.reader({ groupId: "rt-ts-" + Math.random().toString(16).slice(2, 10), since: "earliest" });
  for await (const raw of it) {
    scanned++;
    let env: Record<string, unknown>;
    try {
      env = JSON.parse(Buffer.from(raw).toString());
    } catch {
      continue;
    }
    if (env["event_id"] === wantId) {
      found = env;
      break;
    }
    if (Date.now() > deadline) break;
  }

  rmSync(projectDir, { recursive: true, force: true });

  if (found) {
    console.log(
      `READ matched after scanning ${scanned} msgs: ` +
        `event_type=${String(found["event_type"])}, ` +
        `device=${String(found["device_identity"]).slice(0, 24)}`,
    );
    console.log("PASS: Tn.info() -> Kafka -> handler.reader() round-trip works");
    return 0;
  }
  console.log(`FAIL: event_id ${wantId} not seen via reader() (scanned ${scanned})`);
  return 1;
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    console.error("ERROR:", e);
    process.exit(1);
  });
