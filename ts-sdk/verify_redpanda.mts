// End-to-end TS verification of the KafkaHandler against live Redpanda Cloud.
// Companion to samples/redpanda-firehose/verify_py.py (the Python equivalent).
//
// Drives the real KafkaHandler (emit -> durable outbox -> worker -> publish
// -> kafkajs -> Redpanda Cloud), then consumes the topic tail and confirms
// the exact event_id came back through the broker.
//
// Lives in ts-sdk (not the sample dir) so the optional `kafkajs` dep and the
// handler's `./src/handlers/kafka.js` import both resolve from ts-sdk/node_modules.
//
//   cd ts-sdk
//   npm install --no-save kafkajs
//   RP_USERNAME=tn-firehose RP_PASSWORD=... KAFKAJS_NO_PARTITIONER_WARNING=1 \
//     node --import tsx ./verify_redpanda.mts
//
// PASS proven 2026-06-05: TS produce + consume round-trip through
// d8guu3lvi6v3jq8i6k2g.any.us-east-1.mpx.prd.cloud.redpanda.com.

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { KafkaHandler } from "./src/handlers/kafka.js";
import { Kafka, type Consumer } from "kafkajs";

const BOOTSTRAP = "d8guu3lvi6v3jq8i6k2g.any.us-east-1.mpx.prd.cloud.redpanda.com:9092";
const TOPIC = "tn.firehose.00000000-0000-0000-0000-000000000001";

const USER = process.env["RP_USERNAME"] ?? "";
const PASS = process.env["RP_PASSWORD"] ?? "";

function sealedEnvelope(eventId: string, marker: string): { env: Record<string, unknown>; raw: string } {
  // TN-shaped envelope. The publish path reads event_type + event_id; the
  // rest mirrors what tn.info() seals (telemetry profile: no chain/sign).
  const env: Record<string, unknown> = {
    device_identity: "did:key:z6MkTSverify" + "0".repeat(30),
    timestamp: new Date(0).toISOString(), // fixed — Date.now banned in some ctx; fine here
    event_id: eventId,
    event_type: "verify.ts.message",
    level: "info",
    public_fields: { marker, source: "ts-verify" },
  };
  const raw = JSON.stringify(env) + "\n";
  return { env, raw };
}

async function main(): Promise<number> {
  if (!USER || !PASS) {
    console.error("set RP_USERNAME and RP_PASSWORD");
    return 2;
  }

  const marker = "TSVERIFY-" + randomUUID().slice(0, 12);
  const eventId = randomUUID();
  console.log("marker:", marker);
  console.log("event_id:", eventId);

  // 1. Consumer to capture the high-watermark BEFORE send (topic has many msgs)
  const kafka = new Kafka({
    clientId: "ts-verify",
    brokers: [BOOTSTRAP],
    ssl: true,
    sasl: { mechanism: "scram-sha-256", username: USER, password: PASS },
  });
  const admin = kafka.admin();
  await admin.connect();
  const offsets = await admin.fetchTopicOffsets(TOPIC);
  const watermark = BigInt(offsets[0]!.high);
  await admin.disconnect();
  console.log("high-watermark before send:", watermark.toString());

  // 2. Drive the real KafkaHandler
  const outboxDir = mkdtempSync(join(tmpdir(), "tn-ts-verify-"));
  const handler = new KafkaHandler("verify", {
    outboxDir,
    bootstrap: BOOTSTRAP,
    topic: TOPIC,
    sasl: { mechanism: "SCRAM-SHA-256", user: USER, pass: PASS },
    compressionType: "gzip",
    acks: "all",
  });
  await handler.whenReady();

  const { env, raw } = sealedEnvelope(eventId, marker);
  handler.emit(env, raw);
  await handler.closeAsync({ timeoutMs: 30000 });
  console.log("sent + drained outbox");

  // 3. Read forward from the watermark, match event_id
  const consumer: Consumer = kafka.consumer({ groupId: "ts-verify-" + randomUUID().slice(0, 8) });
  await consumer.connect();
  await consumer.subscribe({ topic: TOPIC, fromBeginning: true });

  const found = await new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => resolve(false), 30000);
    void consumer.run({
      eachMessage: async ({ message }) => {
        if (!message.value) return;
        let parsed: Record<string, unknown>;
        try {
          parsed = JSON.parse(message.value.toString());
        } catch {
          return;
        }
        if (parsed["event_id"] === eventId) {
          console.log(
            `  matched event_id ${eventId} at offset ${message.offset}, ` +
              `type=${String(parsed["event_type"])}, ` +
              `device=${String(parsed["device_identity"]).slice(0, 24)}`,
          );
          clearTimeout(timer);
          resolve(true);
        }
      },
    });
    // kafkajs requires run() to be active before seek(); seek on next tick.
    setTimeout(() => consumer.seek({ topic: TOPIC, partition: 0, offset: watermark.toString() }), 500);
  });
  await consumer.disconnect();

  if (found) {
    console.log("PASS: TS KafkaHandler -> Redpanda Cloud round-trip works");
    return 0;
  }
  console.log("FAIL: did not find the TS event_id in the topic");
  return 1;
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    console.error("ERROR:", e);
    process.exit(1);
  });
