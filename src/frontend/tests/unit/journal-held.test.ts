import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import type { JournalEvent, LogLevel } from "../../src/data/events.svelte";

import { HELD, trimHeld } from "../../src/data/journal-held";

let seq = 0;
const log = (level: LogLevel): JournalEvent => ({
  seq: ++seq,
  at: 0,
  kind: "log",
  level,
  source: "fircd",
  message: `${level} ${seq}`,
});
const dns = (): JournalEvent => ({
  seq: ++seq,
  at: 0,
  kind: "dns",
  client: "192.168.1.42",
  name: "a.example",
  qtype: "A",
  rcode: "NOERROR",
  decision: "no-match",
  reals: [],
});
const bypass = (): JournalEvent => ({
  seq: ++seq,
  at: 0,
  kind: "bypass",
  client: "192.168.1.42",
  dst: "142.250.1.1",
  proto: "tcp",
  how: "sni",
  name: "a.example",
  repeats: 0,
});
const many = (n: number, make: () => JournalEvent) => Array.from({ length: n }, make);

describe("trimHeld", () => {
  // Catches caps that differ from the daemon's rings, so the page keeps more or less than the daemon.
  it("holds as much of each class as the daemon's ring for it", () => {
    assert.deepStrictEqual(HELD, { debug: 512, info: 512, alert: 256, traffic: 4096 });
  });
  // Catches a trim by total count, which lets DNS and debug traffic push a warning out of the page.
  it("keeps a warning past any number of newer DNS events and debug lines", () => {
    seq = 0;
    const warn = log("warn");
    const held = trimHeld([warn, ...many(6000, dns), ...many(900, () => log("debug"))]);
    assert.strictEqual(held[0], warn);
    assert.strictEqual(held.length, 1 + 4096 + 512);
  });
  // Catches a class trimmed from its newest end, or the classes put back out of seq order.
  it("drops the oldest of each class and keeps the rest in seq order", () => {
    seq = 0;
    const all = [
      ...many(300, () => log("error")),
      ...many(600, () => log("info")),
      ...many(4100, bypass),
      ...many(600, () => log("debug")),
    ];
    const held = trimHeld(all);
    const seqs = held.map((e) => e.seq);
    assert.deepStrictEqual(
      seqs,
      [...seqs].sort((a, b) => a - b),
    );
    assert.strictEqual(held.length, 256 + 512 + 4096 + 512);
    assert.strictEqual(held[0].seq, 45);
    assert.strictEqual(held.filter((e) => e.kind === "bypass")[0].seq, 905);
    assert.strictEqual(held.at(-1)?.seq, all.at(-1)?.seq);
  });
  // Catches warn and error counted apart, or DNS and bypass, which each share one daemon ring.
  it("counts warn with error and DNS with bypass", () => {
    seq = 0;
    const held = trimHeld([
      ...many(200, () => log("warn")),
      ...many(200, () => log("error")),
      ...many(3000, dns),
      ...many(3000, bypass),
    ]);
    assert.strictEqual(held.filter((e) => e.kind === "log").length, 256);
    assert.strictEqual(held.filter((e) => e.kind !== "log").length, 4096);
  });
  it("returns the same events when nothing is over its cap", () => {
    seq = 0;
    const few = [log("info"), dns(), log("warn")];
    assert.deepStrictEqual(trimHeld(few), few);
  });
});
