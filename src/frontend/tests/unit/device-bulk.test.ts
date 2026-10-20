import { deepStrictEqual, notStrictEqual, strictEqual } from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { aggregate, applyBulk, replaceWith, type BulkEdits } from "../../src/utils/device-bulk.ts";
import type { Host, PickerPolicy } from "../../src/utils/device-picker.ts";

const POLICIES: PickerPolicy[] = [
  { name: "Policy0", description: "Kids", devices: 2 },
  { name: "Policy1", devices: 1 },
];

const TV = "aa:00:00:00:00:01";
const LAPTOP = "aa:00:00:00:00:02";
const PHONE = "aa:00:00:00:00:03";

const host = (mac: string, name: string, ip: string, policy: string): Host => ({
  mac,
  name,
  ip,
  ip6: [],
  active: true,
  registered: true,
  policy,
});

const HOSTS: Host[] = [
  host(TV, "TV", "192.168.1.5", "Policy0"),
  host(LAPTOP, "Laptop", "192.168.1.6", ""),
  host(PHONE, "Phone", "192.168.1.7", "Policy0"),
];

const edits = (policies: [string, boolean][] = [], macs: [string, boolean][] = []): BulkEdits => ({
  policies: new Map(policies),
  macs: new Map(macs),
});

const sel = (allow: string[], deny: string[] = []) => ({ allow, deny });

describe("applyBulk on one group", () => {
  // Catches a host switched off in an every-device group written as anything but a deny of its MAC.
  it("off in an «all» group adds the MAC to deny", () => {
    const r = applyBulk(sel([]), edits([], [[LAPTOP, false]]), "keep", POLICIES, HOSTS);
    deepStrictEqual(r, { sel: sel([], [`mac:${LAPTOP}`]), refused: [] });
  });

  // Catches switching a host back on in an «all» group leaving its deny behind.
  it("on in an «all» group removes the MAC's deny", () => {
    const r = applyBulk(
      sel([], [`mac:${LAPTOP}`]),
      edits([], [[LAPTOP, true]]),
      "keep",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(r, { sel: sel([]), refused: [] });
  });

  // Catches a host switched on in an «only» group not added to allow, or the existing allow lost.
  it("on in an «only» group adds the MAC to allow", () => {
    const r = applyBulk(sel([`mac:${TV}`]), edits([], [[LAPTOP, true]]), "keep", POLICIES, HOSTS);
    deepStrictEqual(r, { sel: sel([`mac:${TV}`, `mac:${LAPTOP}`]), refused: [] });
  });

  // Catches a host switched off in an «only» group kept in allow or turned into a deny.
  it("off in an «only» group removes the MAC from allow", () => {
    const r = applyBulk(
      sel([`mac:${TV}`, `mac:${LAPTOP}`]),
      edits([], [[LAPTOP, false]]),
      "keep",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(r, { sel: sel([`mac:${TV}`]), refused: [] });
  });

  // Catches hosts applied before policies, which refuses a host its own policy is about to free.
  it("a policy switched on first lets a host of it be switched off", () => {
    const r = applyBulk(
      sel([], ["policy:Kids"]),
      edits([["Policy0", true]], [[PHONE, false]]),
      "keep",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(r, { sel: sel([], [`mac:${PHONE}`]), refused: [] });
  });

  // Catches keep mode forcing one mode on every group instead of each group's own.
  it("keep mode leaves each group in its own mode", () => {
    const all = applyBulk(sel([]), edits([], [[LAPTOP, true]]), "keep", POLICIES, HOSTS);
    deepStrictEqual(all, { sel: null, refused: [] });
    const only = applyBulk(
      sel([`mac:${TV}`]),
      edits([], [[LAPTOP, true]]),
      "keep",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(only.sel, sel([`mac:${TV}`, `mac:${LAPTOP}`]));
  });

  // Catches «every device» keeping an allow or dropping a deny.
  it("«all» mode drops the allows and keeps the denies", () => {
    const r = applyBulk(
      sel([`mac:${TV}`, "policy:Kids"], [`mac:${PHONE}`]),
      edits(),
      "all",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(r, { sel: sel([], [`mac:${PHONE}`]), refused: [] });
  });

  // Catches «only» mode on an every-device group not writing the chosen host as an allow.
  it("«only» mode on an «all» group writes the switched-on host as an allow", () => {
    const r = applyBulk(sel([]), edits([], [[LAPTOP, true]]), "only", POLICIES, HOSTS);
    deepStrictEqual(r, { sel: sel([`mac:${LAPTOP}`]), refused: [] });
  });

  // Catches an «only» result with nothing on being stored, which the daemon reads as every device.
  it("«only» with nothing on is refused and the group stays as it was", () => {
    deepStrictEqual(applyBulk(sel([]), edits(), "only", POLICIES, HOSTS), {
      sel: null,
      refused: [{ kind: "nothing-chosen" }],
    });
    deepStrictEqual(
      applyBulk(sel([`mac:${LAPTOP}`]), edits([], [[LAPTOP, false]]), "keep", POLICIES, HOSTS),
      { sel: null, refused: [{ kind: "nothing-chosen" }] },
    );
  });

  // Catches a host locked off by its policy being flipped anyway, the reason dropped, or the other edits lost with it.
  it("a host locked by its denied policy is refused with the reason", () => {
    const r = applyBulk(
      sel([], ["policy:Kids"]),
      edits(
        [],
        [
          [TV, true],
          [LAPTOP, false],
        ],
      ),
      "keep",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(r, {
      sel: sel([], ["policy:Kids", `mac:${LAPTOP}`]),
      refused: [{ kind: "locked", mac: TV, note: { kind: "policy-off", policy: "Kids" } }],
    });
  });

  // Catches a host denied by a manual address line being flipped, or the group changed.
  it("a host locked by a manual deny is refused and the group is unchanged", () => {
    const r = applyBulk(
      sel([], ["192.168.1.6"]),
      edits([], [[LAPTOP, true]]),
      "keep",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(r, {
      sel: null,
      refused: [{ kind: "locked", mac: LAPTOP, note: { kind: "manual-off" } }],
    });
  });

  // Catches a host switched on while the same batch denies its policy being flipped past the deny.
  it("a host whose policy the batch denies is refused as locked", () => {
    const r = applyBulk(
      sel([]),
      edits([["Policy0", false]], [[TV, true]]),
      "keep",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(r, {
      sel: sel([], ["policy:Policy0"]),
      refused: [{ kind: "locked", mac: TV, note: { kind: "policy-off", policy: "Kids" } }],
    });
  });

  // Catches a host of a policy switched off in an «only» group refused instead of switched off.
  it("«only»: a policy off and a host of it off drops the host's allow", () => {
    const r = applyBulk(
      sel([`mac:${TV}`, `mac:${PHONE}`]),
      edits([["Policy0", false]], [[TV, false]]),
      "keep",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(r, { sel: sel([`mac:${PHONE}`]), refused: [] });
  });

  // Catches a host of a policy switched off in an «only» group refused instead of switched on.
  it("«only»: a policy off and a host of it on adds the host's allow", () => {
    const r = applyBulk(
      sel([`mac:${PHONE}`]),
      edits([["Policy0", false]], [[TV, true]]),
      "keep",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(r, { sel: sel([`mac:${PHONE}`, `mac:${TV}`]), refused: [] });
  });

  // Catches a policy already in the target state flipped anyway, turning it the other way.
  it("a policy targeted to the state it has changes nothing", () => {
    deepStrictEqual(
      applyBulk(sel(["policy:Kids"]), edits([["Policy0", true]]), "keep", POLICIES, HOSTS),
      { sel: null, refused: [] },
    );
    deepStrictEqual(
      applyBulk(sel([], ["policy:Kids"]), edits([["Policy0", false]]), "keep", POLICIES, HOSTS),
      { sel: null, refused: [] },
    );
  });

  // Catches a MAC the router does not list having no row to edit, so its edit is lost or throws.
  it("a MAC the router does not list can be switched off", () => {
    const r = applyBulk(
      sel([]),
      edits([], [["aa:00:00:00:00:99", false]]),
      "keep",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(r, { sel: sel([], ["mac:aa:00:00:00:00:99"]), refused: [] });
  });

  // Catches nothing-chosen dropping the group's other refusals from the warning.
  it("nothing-chosen keeps the group's other refusals", () => {
    const r = applyBulk(
      sel([`mac:${LAPTOP}`], ["policy:Kids"]),
      edits(
        [],
        [
          [TV, true],
          [LAPTOP, false],
        ],
      ),
      "keep",
      POLICIES,
      HOSTS,
    );
    deepStrictEqual(r, {
      sel: null,
      refused: [
        { kind: "locked", mac: TV, note: { kind: "policy-off", policy: "Kids" } },
        { kind: "nothing-chosen" },
      ],
    });
  });

  // Catches a policy no key can name being written anyway, or refused silently.
  it("a policy whose name is taken is refused as taken", () => {
    const taken: PickerPolicy[] = [
      { name: "Policy1", description: "Policy0", devices: 0 },
      { name: "Policy0", description: "", devices: 2 },
    ];
    deepStrictEqual(applyBulk(sel([]), edits([["Policy0", false]]), "keep", taken, HOSTS), {
      sel: null,
      refused: [{ kind: "taken", policy: "Policy0" }],
    });
  });

  // Catches an untouched group reported changed because joinSelector reorders or normalises its entries.
  it("no edits change no group, whatever its stored shape", () => {
    const shapes = [
      undefined,
      sel([]),
      sel([`mac:${TV}`, "policy:Kids"]),
      sel(["mac:AA-00-00-00-00-01"]),
      sel(["192.168.1.0/24"], [`mac:${PHONE}`]),
      sel([`mac:${LAPTOP}`], [`mac:${LAPTOP}`]),
      sel([], ["policy:Policy0", "mac:AA:00:00:00:00:02"]),
    ];
    for (const shape of shapes) {
      deepStrictEqual(applyBulk(shape, edits(), "keep", POLICIES, HOSTS), {
        sel: null,
        refused: [],
      });
    }
    deepStrictEqual(
      applyBulk(sel(["mac:AA-00-00-00-00-01"]), edits([], [[TV, true]]), "keep", POLICIES, HOSTS),
      { sel: null, refused: [] },
    );
  });
});

describe("aggregate over the selected groups", () => {
  const groups = [sel([]), sel([], [`mac:${TV}`]), sel(["policy:Kids"])];

  // Catches a group's own deny ignored, or every group counted under one mode.
  it("counts each row under each group's own mode", () => {
    const a = aggregate(groups, "keep", POLICIES, HOSTS);
    deepStrictEqual(
      [...a.policies],
      [
        ["Policy0", 3],
        ["Policy1", 2],
      ],
    );
    deepStrictEqual(a.macs.get(TV), 2);
    deepStrictEqual(a.macs.get(LAPTOP), 2);
    deepStrictEqual(a.macs.get(PHONE), 3);
  });

  // Catches the rows shown counted under the groups' modes rather than the mode the edit will use.
  it("counts under the edit's mode when one is chosen", () => {
    const all = aggregate(groups, "all", POLICIES, HOSTS);
    deepStrictEqual([...all.policies.values()], [3, 3]);
    deepStrictEqual(
      [TV, LAPTOP, PHONE].map((m) => all.macs.get(m)),
      [2, 3, 3],
    );
    const only = aggregate(groups, "only", POLICIES, HOSTS);
    deepStrictEqual([...only.policies.values()], [1, 0]);
    deepStrictEqual(
      [TV, LAPTOP, PHONE].map((m) => only.macs.get(m)),
      [1, 0, 1],
    );
  });

  // Catches a stored MAC the router no longer lists getting no row to edit.
  it("a MAC only a selector names still has a row", () => {
    const a = aggregate([sel([], ["mac:aa:00:00:00:00:99"]), sel([])], "keep", POLICIES, HOSTS);
    strictEqual(a.macs.get("aa:00:00:00:00:99"), 1);
  });
});

describe("replaceWith", () => {
  // Catches Replace or Reset dirtying a group already at the value in another spelling.
  it("is null for a group already at the value, a fresh copy otherwise", () => {
    const value = sel([`mac:${TV}`]);
    strictEqual(replaceWith(sel(["mac:AA-00-00-00-00-01"]), value), null);
    strictEqual(replaceWith(undefined, sel([])), null);
    const out = replaceWith(sel([]), value);
    deepStrictEqual(out, value);
    notStrictEqual(out, value);
    notStrictEqual(out!.allow, value.allow);
  });
});
