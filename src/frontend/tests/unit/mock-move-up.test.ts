import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

const { activeOf, moveUp } = await import("../../dev/move-up");

const listed = (extra: Record<string, unknown> = {}) => ({
  id: "0a000011",
  interface: ["nwg0", "nwg1"],
  enable: true,
  ...extra,
});
const alive = { state: "alive" as const, since: 1, error: "" };
const dead = { state: "dead" as const, since: 1, error: "timed out" };

describe("the mock's move-up, like the daemon's", () => {
  it("answers 200 at once for a group already on its first entry, whatever its state", () => {
    assert.deepStrictEqual(moveUp(listed(), undefined, { nwg0: dead }), { status: 200 });
    assert.deepStrictEqual(moveUp(listed(), 0, {}), { status: 200 });
  });
  it("moves a group back when its first entry is alive, and refuses it when not", () => {
    assert.deepStrictEqual(moveUp(listed(), 1, { nwg0: alive }), { status: 200 });
    assert.deepStrictEqual(moveUp(listed(), 1, { nwg0: dead }), {
      status: 409,
      error: "nwg0 is not alive",
    });
    assert.deepStrictEqual(moveUp(listed(), 1, {}), { status: 409, error: "nwg0 is not alive" });
  });
  it("refuses a group that is off with 409 and a single entry with 400", () => {
    assert.deepStrictEqual(moveUp(listed({ enable: false }), 0, { nwg0: alive }), {
      status: 409,
      error: "the group is not routed",
    });
    assert.deepStrictEqual(moveUp(listed({ interface: "nwg0" }), undefined, {}), {
      status: 400,
      error: "the group names one interface",
    });
    assert.deepStrictEqual(moveUp(undefined, undefined, {}), {
      status: 404,
      error: "group not exist",
    });
  });
  it("answers the first entry as active for a group that is off", () => {
    assert.strictEqual(activeOf(listed(), 1), "nwg1");
    assert.strictEqual(activeOf(listed({ enable: false }), 1), "nwg0");
    assert.strictEqual(activeOf(listed(), undefined), "nwg0");
  });
});
