// Kafka handler — port of python/tn/handlers/kafka.py.
//
// Streams each accepted envelope as a sealed JSON line to a Kafka-compatible
// broker (Apache Kafka, Confluent Cloud, Redpanda). The message value is the
// raw sealed envelope — byte-identical to a line in `.tn/logs/tn.ndjson` — and
// the message key is the envelope's `event_id`, so all rows for one envelope
// land on the same partition in chain order.
//
// Gated behind an OPTIONAL `kafkajs` dependency (lazy-imported, like the
// firehose handler's optional `ws`). The base wheel/package stays lean; users
// who declare `kind: kafka` install `kafkajs` themselves.
//
// YAML:
//   - kind: kafka
//     name: redpanda-cloud
//     bootstrap: seed-xxx.us-east-1.redpanda.cloud:9092
//     topic: "tn.firehose.<project_id>"   # fixed string, OR "tn.{event_type}"
//     sasl:
//       mechanism: SCRAM-SHA-256
//       user: env:RP_USERNAME             # env:NAME resolves at construction
//       pass: env:RP_PASSWORD
//     client_id: tn-protocol-sdk          # optional
//     compression_type: gzip              # optional (gzip|none; lz4/snappy/zstd need kafkajs plugins)
//     acks: all                           # optional
//
// PARITY NOTE: the publish path mirrors Python exactly (sealed value,
// event_id key, SASL_SSL, idempotent producer). resolved_address() and
// reader() implement the same read-side contract documented in kafka.py —
// see cyaxios/tn-proto#112. The reader() consumer path is UNTESTED in TS
// (no broker round-trip run yet); the publish path is the proven one.

import { AsyncTNHandler, type FilterSpec } from "./base.js";

// Apache Kafka topic rules: [a-zA-Z0-9._-], max 249, not "." or "..".
const _TOPIC_RE = /^[A-Za-z0-9._-]{1,249}$/;

/** Resolve `env:NAME` to process.env[NAME]; pass anything else through.
 *  Mirrors python/tn/handlers/kafka.py::_resolve. */
function resolveEnv(value: string | undefined): string | undefined {
  if (!value) return value;
  if (value.startsWith("env:")) return process.env[value.slice(4)] ?? "";
  return value;
}

/** Validate a rendered topic name. Mirrors Python `_validate_topic`. */
export function validateTopic(topic: string): string {
  if (topic === "." || topic === "..") {
    throw new Error(`kafka: topic ${JSON.stringify(topic)} reserved`);
  }
  if (!_TOPIC_RE.test(topic)) {
    throw new Error(
      `kafka: topic ${JSON.stringify(topic)} contains illegal chars (allowed: a-z A-Z 0-9 . _ -)`,
    );
  }
  return topic;
}

export interface KafkaSasl {
  mechanism?: string; // "PLAIN" | "SCRAM-SHA-256" | "SCRAM-SHA-512"
  user?: string; // literal or "env:NAME"
  pass?: string; // literal or "env:NAME"
}

export interface KafkaHandlerOptions {
  outboxDir: string;
  bootstrap: string;
  /** Topic name. Fixed string, or a `tn.{event_type}` template. */
  topic: string;
  sasl?: KafkaSasl;
  clientId?: string;
  /** "gzip" | "none" (kafkajs built-ins). lz4/snappy/zstd require plugins. */
  compressionType?: string;
  acks?: string; // "all" | "1" | "0"
  filter?: FilterSpec;
  maxRetries?: number;
  backoffInitialMs?: number;
  backoffMaxMs?: number;
}

// Minimal structural types for the bits of kafkajs we touch, so this file
// type-checks without `kafkajs` installed (it's an optional dependency).
interface KjsProducer {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  send(args: {
    topic: string;
    messages: { key?: Buffer; value: Buffer }[];
    acks?: number;
    compression?: number;
  }): Promise<unknown>;
}
interface KjsConsumer {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  subscribe(args: { topic: string; fromBeginning: boolean }): Promise<void>;
  run(args: {
    eachMessage: (p: { message: { value: Buffer | null } }) => Promise<void>;
  }): Promise<void>;
}
interface KjsKafka {
  producer(opts?: { idempotent?: boolean }): KjsProducer;
  consumer(opts: { groupId: string }): KjsConsumer;
}
interface KjsModule {
  Kafka: new (opts: {
    clientId: string;
    brokers: string[];
    ssl?: boolean;
    sasl?: { mechanism: string; username: string; password: string };
  }) => KjsKafka;
  CompressionTypes: { None: number; GZIP: number };
}

/**
 * Kafka / Redpanda fan-out handler. Mirrors python/tn/handlers/kafka.py.
 *
 * @public
 */
export class KafkaHandler extends AsyncTNHandler {
  private readonly _bootstrap: string;
  private readonly _topicTmpl: string;
  private readonly _sasl: KafkaSasl | undefined;
  private readonly _clientId: string;
  private readonly _compression: string;
  private readonly _acks: string;
  private _kafka: KjsKafka | null = null;
  private _producer: KjsProducer | null = null;
  private _kjs: KjsModule | null = null;

  constructor(name: string, opts: KafkaHandlerOptions) {
    const asyncOpts: ConstructorParameters<typeof AsyncTNHandler>[1] = { outboxDir: opts.outboxDir };
    if (opts.filter !== undefined) asyncOpts.filter = opts.filter;
    if (opts.maxRetries !== undefined) asyncOpts.maxRetries = opts.maxRetries;
    if (opts.backoffInitialMs !== undefined) asyncOpts.backoffInitialMs = opts.backoffInitialMs;
    if (opts.backoffMaxMs !== undefined) asyncOpts.backoffMaxMs = opts.backoffMaxMs;
    super(name, asyncOpts);
    this._bootstrap = opts.bootstrap;
    this._topicTmpl = opts.topic;
    this._sasl = opts.sasl;
    this._clientId = opts.clientId ?? "tn-protocol";
    this._compression = (opts.compressionType ?? "gzip").toLowerCase();
    this._acks = opts.acks ?? "all";
  }

  // ──────────────────────────────────────────────────────────────────
  // Read-side contract (see cyaxios/tn-proto#112)
  //   resolved_address() is the sink identity; reader() yields raw sealed
  //   bytes. tn.read() will auto-select file over kafka when both exist.
  //   The publish path is proven; the reader() consumer path is UNTESTED.
  // ──────────────────────────────────────────────────────────────────

  override resolved_address(): string {
    return `kafka://${this._bootstrap}/${this._topicTmpl}`;
  }

  /** Yield raw sealed-envelope bytes from the topic. Same shape as a line
   *  from `.tn/logs/tn.ndjson`. UNTESTED in TS — mirrors Python reader(). */
  async *reader(opts: { groupId?: string; since?: "earliest" | "latest" } = {}): AsyncIterableIterator<Uint8Array> {
    const kjs = await this._loadKjs();
    const kafka = this._buildKafka(kjs);
    const consumer = kafka.consumer({ groupId: opts.groupId ?? `tn-reader-${this.name}` });
    await consumer.connect();
    await consumer.subscribe({ topic: this._topicTmpl, fromBeginning: (opts.since ?? "earliest") === "earliest" });

    // Bridge kafkajs's eachMessage callback into an async iterator via a
    // simple bounded queue + notifier.
    const queue: Uint8Array[] = [];
    let notify: (() => void) | null = null;
    void consumer.run({
      eachMessage: async ({ message }) => {
        if (message.value) queue.push(new Uint8Array(message.value));
        notify?.();
      },
    });
    try {
      // No idle timeout — caller breaks out of the for-await when done.
      for (;;) {
        if (queue.length === 0) {
          await new Promise<void>((r) => {
            notify = r;
          });
          notify = null;
        }
        while (queue.length) yield queue.shift() as Uint8Array;
      }
    } finally {
      await consumer.disconnect();
    }
  }

  // ──────────────────────────────────────────────────────────────────
  // Publish path (proven — mirrors Python _publish)
  // ──────────────────────────────────────────────────────────────────

  protected override async publish(
    envelope: Record<string, unknown>,
    rawLine: string,
  ): Promise<void> {
    const eventType = String(envelope["event_type"] ?? "");
    const eventId = String(envelope["event_id"] ?? "");
    const topic = validateTopic(this._topicTmpl.replace("{event_type}", eventType));

    const producer = await this._ensureProducer();
    const kjs = this._kjs as KjsModule;
    const compression =
      this._compression === "none" ? kjs.CompressionTypes.None : kjs.CompressionTypes.GZIP;
    const acks = this._acks === "all" ? -1 : Number(this._acks);

    try {
      await producer.send({
        topic,
        messages: [
          {
            key: eventId ? Buffer.from(eventId, "utf-8") : undefined,
            value: Buffer.from(rawLine, "utf-8"),
          } as { key?: Buffer; value: Buffer },
        ],
        acks,
        compression,
      });
    } catch (e) {
      // Drop the producer so the retry reconnects, re-throw so the outbox
      // holds the row for redelivery.
      this._producer = null;
      throw e instanceof Error ? e : new Error(String(e));
    }
  }

  protected override finalFlush(): void {
    const p = this._producer;
    this._producer = null;
    if (p) void p.disconnect();
  }

  // ──────────────────────────────────────────────────────────────────
  // Internals
  // ──────────────────────────────────────────────────────────────────

  private async _ensureProducer(): Promise<KjsProducer> {
    if (this._producer) return this._producer;
    const kjs = await this._loadKjs();
    const kafka = this._buildKafka(kjs);
    const producer = kafka.producer({ idempotent: true });
    await producer.connect();
    this._producer = producer;
    return producer;
  }

  private _buildKafka(kjs: KjsModule): KjsKafka {
    if (this._kafka) return this._kafka;
    const opts: ConstructorParameters<KjsModule["Kafka"]>[0] = {
      clientId: this._clientId,
      brokers: [this._bootstrap],
    };
    if (this._sasl) {
      opts.ssl = true;
      opts.sasl = {
        // kafkajs wants lowercase: "plain" | "scram-sha-256" | "scram-sha-512"
        mechanism: (this._sasl.mechanism ?? "plain").toLowerCase(),
        username: resolveEnv(this._sasl.user) ?? "",
        password: resolveEnv(this._sasl.pass) ?? "",
      };
    }
    this._kafka = new kjs.Kafka(opts);
    return this._kafka;
  }

  private async _loadKjs(): Promise<KjsModule> {
    if (this._kjs) return this._kjs;
    try {
      // Non-literal specifier so tsc doesn't resolve the optional dep at build.
      const spec = "kafkajs";
      this._kjs = (await import(spec)) as unknown as KjsModule;
      return this._kjs;
    } catch (e) {
      throw new Error(
        "KafkaHandler requires the optional `kafkajs` package. Install via `npm install kafkajs`.",
        { cause: e },
      );
    }
  }
}
