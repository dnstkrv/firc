import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { pathOfTab, tabFromPath } from "../../src/utils/tab-path.ts";

describe("a tab's address", () => {
  // Catches a tab reached by its internal id instead of the title the UI shows.
  it("is named after the title", () => {
    assert.deepStrictEqual(["groups", "tunnels", "logs", "settings"].map(pathOfTab), [
      "/groups",
      "/tunnels",
      "/journal",
      "/settings",
    ]);
  });

  // Catches the root, an internal id or an unknown path opening anything but Groups.
  it("opens Groups for every address that is not a tab", () => {
    for (const p of ["/", "/logs", "/nope", "/journal/x", ""]) {
      assert.strictEqual(tabFromPath(p), "groups", p);
    }
  });

  // Catches an address mapped back to the wrong tab.
  it("reads each tab back from its address", () => {
    for (const tab of ["groups", "tunnels", "logs", "settings"]) {
      assert.strictEqual(tabFromPath(pathOfTab(tab)), tab);
    }
  });
});
