import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const { journalFocus } = await import("../../src/data/journal-focus.svelte");

describe("journalFocus", () => {
  // Catches a request that repeats its seq, so a second click on the same group changes nothing.
  it("opening the same group twice gives increasing seq", () => {
    journalFocus.open("c4a7e1f0");
    const first = journalFocus.request;
    journalFocus.open("c4a7e1f0");
    const second = journalFocus.request;
    assert.strictEqual(first?.group, "c4a7e1f0");
    assert.strictEqual(second?.group, "c4a7e1f0");
    assert.ok(second!.seq > first!.seq);
  });
});
