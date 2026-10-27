import { deepStrictEqual, strictEqual } from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import type { Host, PickerPolicy } from "../../src/utils/device-picker.ts";
import { outsideLan, policyOutside, uncoveredSegments } from "../../src/utils/lan-coverage.ts";

const POLICIES: PickerPolicy[] = [{ name: "Policy0", description: "Kids", devices: 3 }];

const A: Host = {
  mac: "aa:00:00:00:00:01",
  name: "A",
  ip: "192.168.1.5",
  ip6: [],
  active: true,
  registered: true,
  policy: "Policy0",
  segment: "br0",
  intercepted: true,
};
const B: Host = {
  ...A,
  mac: "aa:00:00:00:00:02",
  name: "B",
  ip: "192.168.2.7",
  segment: "br1",
  intercepted: false,
};
const C: Host = {
  ...A,
  mac: "aa:00:00:00:00:03",
  name: "C",
  ip: "192.168.3.9",
  policy: "",
  segment: "br2",
  intercepted: false,
};
const D: Host = {
  ...A,
  mac: "aa:00:00:00:00:04",
  name: "D",
  ip: "",
  segment: undefined,
  intercepted: true,
};
const HOSTS = [A, B, C, D];

const group = (name: string, allow: string[] = [], deny: string[] = [], enable = true) => ({
  name,
  enable,
  devices: { allow, deny },
});

describe("outsideLan", () => {
  // Catches: a missing field (an older daemon) read as outside.
  it("is true only for intercepted false", () => {
    strictEqual(outsideLan(B), true);
    strictEqual(outsideLan(A), false);
    strictEqual(outsideLan({ ...A, intercepted: undefined }), false);
  });
});

describe("policyOutside", () => {
  // Catches: counting intercepted hosts, other policies, or one MAC twice.
  it("counts the policy's hosts outside the LAN once per MAC", () => {
    strictEqual(policyOutside(HOSTS, "Policy0"), 1);
    strictEqual(policyOutside([...HOSTS, { ...B, ip: "192.168.2.8" }], "Policy0"), 1);
    strictEqual(policyOutside(HOSTS, "Policy1"), 0);
  });
});

describe("uncoveredSegments", () => {
  // Catches: mode "For every device" skipped, or segments unsorted.
  it("an every-device group covers every outside host", () => {
    deepStrictEqual(uncoveredSegments([group("All")], HOSTS, POLICIES, ["br0"]), [
      { segment: "br1", groups: ["All"] },
      { segment: "br2", groups: ["All"] },
    ]);
  });

  // Catches: a disabled group counted, or a policy allow not followed.
  it("follows policies and skips disabled groups", () => {
    deepStrictEqual(
      uncoveredSegments(
        [group("Kids", ["policy:Policy0"]), group("Off", ["mac:aa:00:00:00:00:03"], [], false)],
        HOSTS,
        POLICIES,
        ["br0"],
      ),
      [{ segment: "br1", groups: ["Kids"] }],
    );
  });

  // Catches: a denied device still reported.
  it("skips a denied device", () => {
    deepStrictEqual(
      uncoveredSegments([group("All", [], ["mac:aa:00:00:00:00:02"])], HOSTS, POLICIES, ["br0"]),
      [{ segment: "br2", groups: ["All"] }],
    );
  });

  // Catches: the draft list ignored, so the block outlives the add button.
  it("drops segments the list already holds", () => {
    deepStrictEqual(uncoveredSegments([group("All")], HOSTS, POLICIES, ["br0", "br1"]), [
      { segment: "br2", groups: ["All"] },
    ]);
  });

  // Catches: a group named twice in one segment, or groups out of input order.
  it("names each group once, in input order", () => {
    deepStrictEqual(
      uncoveredSegments(
        [group("Z"), group("A")],
        [B, { ...B, mac: "aa:00:00:00:00:09" }],
        POLICIES,
        [],
      ),
      [{ segment: "br1", groups: ["Z", "A"] }],
    );
  });

  // Catches: interception off still warning.
  it("is empty when every host is intercepted", () => {
    const all = HOSTS.map((h) => ({ ...h, intercepted: true }));
    deepStrictEqual(uncoveredSegments([group("All")], all, POLICIES, []), []);
  });
});
