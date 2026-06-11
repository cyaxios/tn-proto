// Test-harness helpers shared by the Alice scenarios. Mirrors the
// Python ScenarioContext at python/scenarios/_harness/scenario.py
// with a slimmer surface — node:test does the assertion + reporting,
// so this is just the timer + invariant helpers and a Tn-ephemeral
// lifecycle wrapper.

import { strict as assert } from "node:assert";
import { Tn } from "../../src/tn.js";

export interface ScenarioMetrics {
  [key: string]: number | string | boolean | (number | string)[] | Record<string, unknown>;
}

export class ScenarioContext {
  readonly metrics: ScenarioMetrics = {};
  private readonly invariants: Array<{ name: string; ok: boolean }> = [];

  /** Time a sync block in milliseconds, recording into metrics. */
  timer<T>(name: string, body: () => T): T {
    const t0 = performance.now();
    const result = body();
    this.metrics[name] = performance.now() - t0;
    return result;
  }

  /** Time an async block in milliseconds. */
  async timerAsync<T>(name: string, body: () => Promise<T>): Promise<T> {
    const t0 = performance.now();
    const result = await body();
    this.metrics[name] = performance.now() - t0;
    return result;
  }

  /** Time a sync block in microseconds (samples accumulate; record
   * mean / count via finalizeUsCounter). */
  timerUs<T>(name: string, body: () => T): T {
    const t0 = performance.now();
    const result = body();
    const us = (performance.now() - t0) * 1000;
    const samples = (this.metrics[`${name}_samples`] as number[]) ?? [];
    samples.push(us);
    this.metrics[`${name}_samples`] = samples;
    return result;
  }

  /** Record a single value into metrics. Last-write-wins for the same key. */
  record(name: string, value: ScenarioMetrics[string]): void {
    this.metrics[name] = value;
  }

  /** Assert a named invariant. Records the result and throws on failure. */
  assertInvariant(name: string, ok: boolean, msg?: string): void {
    this.invariants.push({ name, ok });
    assert.ok(ok, msg ?? `invariant failed: ${name}`);
  }

  /** Build a fresh ephemeral Tn instance for the scenario to drive. */
  static async newTn(): Promise<Tn> {
    return Tn.ephemeral({ stdout: false });
  }
}
