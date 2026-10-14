import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { modifierLabel } from "../../src/utils/keys";

describe("modifierLabel", () => {
  // Catches a helper that names Ctrl on a Mac, whatever the platform string looks like there.
  it("names the command key on Apple platforms", () => {
    for (const platform of ["MacIntel", "macOS", "iPhone", "iPad"]) {
      assert.strictEqual(modifierLabel(platform), "⌘", platform);
    }
  });

  // Catches a helper that hands ⌘ to every platform, or to an unknown one.
  it("names Ctrl everywhere else", () => {
    for (const platform of ["Win32", "Windows", "Linux x86_64", "Linux armv8l", "Android", ""]) {
      assert.strictEqual(modifierLabel(platform), "Ctrl", platform);
    }
  });
});
