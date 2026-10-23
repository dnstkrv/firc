import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { isUrlText, searchCatalog } from "../../src/modules/groups/list-catalog.ts";

const src = (id: string, names: string[]) => ({
  id,
  url: `https://raw.githubusercontent.com/${id}/rules/{}.srs`,
  names,
});

describe("catalog search", () => {
  // Catches a case-sensitive match.
  it("matches regardless of case", () => {
    const r = searchCatalog({ sources: [src("a", ["youtube"])] }, "YouTube");
    assert.deepStrictEqual(
      r.rows.map((x) => x.name),
      ["youtube"],
    );
  });

  // Catches exact, prefix and inner matches sorted in list order or by length alone.
  it("orders exact, then prefix, then the rest, shorter first", () => {
    const r = searchCatalog(
      { sources: [src("a", ["youtube-dl", "youtube", "ayou", "you"])] },
      "you",
    );
    assert.deepStrictEqual(
      r.rows.map((x) => x.name),
      ["you", "youtube", "youtube-dl", "ayou"],
    );
  });

  // Catches one row per name instead of per source, or the source order lost.
  it("lists a name from each source with its own url", () => {
    const r = searchCatalog(
      { sources: [src("sagernet", ["youtube"]), src("hoaxisr", ["youtube"])] },
      "youtube",
    );
    assert.deepStrictEqual(r.rows, [
      {
        name: "youtube",
        source: "sagernet",
        url: "https://raw.githubusercontent.com/sagernet/rules/youtube.srs",
      },
      {
        name: "youtube",
        source: "hoaxisr",
        url: "https://raw.githubusercontent.com/hoaxisr/rules/youtube.srs",
      },
    ]);
  });

  // Catches a missing cap or a wrong remainder count.
  it("caps rows at 50 and counts the rest", () => {
    const names = Array.from({ length: 60 }, (_, i) => `site${i}`);
    const r = searchCatalog({ sources: [src("a", names)] }, "site");
    assert.strictEqual(r.rows.length, 50);
    assert.strictEqual(r.more, 10);
  });

  // Catches an empty query matching every name.
  it("finds nothing for an empty query", () => {
    const r = searchCatalog({ sources: [src("a", ["x"])] }, "");
    assert.deepStrictEqual(r, { rows: [], more: 0 });
  });
});

describe("url text", () => {
  // Catches a bare host path being taken for a URL, or a scheme not being recognised.
  it("is text containing a scheme separator", () => {
    assert.strictEqual(isUrlText("https://x"), true);
    assert.strictEqual(isUrlText("raw.githubusercontent.com/a"), false);
  });
});
