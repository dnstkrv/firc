import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import {
  admitsEveryDeviceOf,
  computeOverlaps,
  type OverlapGroup,
} from "../../src/modules/groups/overlap.ts";

const rule = (id: string, text = "meta.com", enable = true, proto?: string) => ({
  id,
  enable,
  rule: text,
  type: "namespace",
  ...(proto ? { proto } : {}),
});

const group = (
  id: string,
  allow: string[] = [],
  deny: string[] = [],
  rules = [rule(`r${id}`)],
  enable = true,
): OverlapGroup => ({ id, name: `group ${id}`, enable, devices: { allow, deny }, rules });

describe("which repeated rule is marked, and how", () => {
  // Catches the upper copy marked too, or an unscoped upper group not read as covering every device.
  it("only the later copy is marked, shadowed by an unscoped upper group", () => {
    const marks = computeOverlaps([group("a"), group("b", ["192.168.1.5"])]);
    assert.strictEqual(marks.get("ra"), undefined);
    assert.deepStrictEqual(marks.get("rb"), {
      kind: "shadowed",
      groupId: "a",
      groupName: "group a",
      ruleId: "ra",
    });
  });

  // Catches a scoped upper group read as covering every device.
  it("a scoped upper group above an unscoped one splits the name", () => {
    assert.strictEqual(
      computeOverlaps([group("a", ["192.168.1.5"]), group("b")]).get("rb")?.kind,
      "split",
    );
  });

  // Catches allow compared in order, untrimmed, or deny compared the wrong way round.
  it("the same allow set in another order with fewer denies shadows", () => {
    const upper = { allow: ["x", " y "], deny: ["z"] };
    assert.strictEqual(admitsEveryDeviceOf(upper, { allow: ["y", "x"], deny: ["z", "w"] }), true);
    assert.strictEqual(admitsEveryDeviceOf(upper, { allow: ["y", "x"], deny: [] }), false);
    assert.strictEqual(
      admitsEveryDeviceOf({ allow: ["x"], deny: [] }, { allow: ["x", "y"], deny: [] }),
      false,
    );
  });

  // Catches the second clause skipped for an upper group with denies only, or a deny-only group taken as "every device".
  it("an upper group with denies only shadows by the second clause alone", () => {
    assert.strictEqual(
      admitsEveryDeviceOf({ allow: [], deny: ["x"] }, { allow: [], deny: ["x", "z"] }),
      true,
    );
    assert.strictEqual(
      admitsEveryDeviceOf({ allow: [], deny: ["x"] }, { allow: [], deny: [] }),
      false,
    );
    assert.strictEqual(
      admitsEveryDeviceOf({ allow: [], deny: ["x"] }, { allow: ["y"], deny: ["x"] }),
      false,
    );
    assert.strictEqual(
      admitsEveryDeviceOf({ allow: [], deny: [] }, { allow: ["y"], deny: ["z"] }),
      true,
    );
  });

  // Catches a disabled group or rule marking, or a disabled later copy left unmarked.
  it("a disabled group or rule marks nothing, a disabled later copy is still marked", () => {
    assert.strictEqual(
      computeOverlaps([group("a", [], [], undefined, false), group("b")]).get("rb"),
      undefined,
    );
    assert.strictEqual(
      computeOverlaps([group("a", [], [], [rule("ra", "meta.com", false)]), group("b")]).get("rb"),
      undefined,
    );
    assert.strictEqual(
      computeOverlaps([group("a"), group("b", [], [], [rule("rb", "meta.com", false)])]).get("rb")
        ?.kind,
      "shadowed",
    );
    assert.strictEqual(
      computeOverlaps([group("a"), group("b", [], [], undefined, false)]).get("rb")?.kind,
      "shadowed",
    );
  });

  // Catches the first earlier copy named although a later earlier group shadows.
  it("names the first earlier group that shadows, else the first earlier one", () => {
    const shadowed = computeOverlaps([group("a", ["x"]), group("b"), group("c", ["y"])]).get("rc");
    assert.deepStrictEqual([shadowed?.kind, shadowed?.groupId], ["shadowed", "b"]);
    const split = computeOverlaps([group("a", ["x"]), group("b", ["z"]), group("c", ["y"])]).get(
      "rc",
    );
    assert.deepStrictEqual([split?.kind, split?.groupId], ["split", "a"]);
  });

  // Catches a repeat inside one group left unmarked, or its first copy marked.
  it("a second copy in one group is shadowed by that group", () => {
    const marks = computeOverlaps([group("a", ["x"], [], [rule("r1"), rule("r2")])]);
    assert.strictEqual(marks.get("r1"), undefined);
    assert.deepStrictEqual([marks.get("r2")?.kind, marks.get("r2")?.ruleId], ["shadowed", "r1"]);
  });

  // Catches protocol or ports dropped from what makes two rules the same.
  it("another protocol is another rule", () => {
    const marks = computeOverlaps([
      group("a", [], [], [rule("ra", "10.0.0.0/8", true, "udp")]),
      group("b", [], [], [rule("rb", "10.0.0.0/8", true, "tcp")]),
    ]);
    assert.strictEqual(marks.get("rb"), undefined);
  });

  // Catches blank selector entries counted as devices.
  it("blank selector entries are ignored", () => {
    assert.strictEqual(
      admitsEveryDeviceOf({ allow: [" ", ""], deny: [""] }, { allow: ["y"], deny: [] }),
      true,
    );
    assert.strictEqual(
      admitsEveryDeviceOf({ allow: ["x", ""], deny: [] }, { allow: ["x"], deny: [" "] }),
      true,
    );
  });
});
