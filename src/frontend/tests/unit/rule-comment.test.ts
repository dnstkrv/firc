import { strictEqual } from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { groupsFromFile } from "../../src/modules/groups/groups-data.ts";
import { cleanComment } from "../../src/utils/rule-comment.ts";

const bytes = (s: string) => new TextEncoder().encode(s).length;

const fileWith = (rules: Record<string, unknown>[]) =>
  JSON.stringify({
    groups: [{ id: "a3509784", name: "G", interface: "eth0", enable: true, rules }],
  });

describe("cleanComment", () => {
  // Catches a newline kept, or dropped so the words run together.
  it("turns a newline into a space", () => {
    strictEqual(cleanComment("a\nb"), "a b");
  });

  // Catches C0, DEL, C1 or a line separator left for the daemon to refuse.
  it("turns every character the daemon refuses into a space", () => {
    strictEqual(cleanComment("\tx\u0007y\u0085z\u2028w\u2029v\u007f"), "x y z w v");
  });

  // Catches inner spaces the user typed collapsed, or edges left untrimmed.
  it("keeps inner spaces and trims the ends", () => {
    strictEqual(cleanComment("  a  \r\n  b  "), "a      b");
  });

  // Catches a lone surrogate let through, which the daemon's JSON parser refuses.
  it("turns a lone surrogate into a space", () => {
    strictEqual(cleanComment("x\ud800"), "x");
    strictEqual(cleanComment("\udc00y\ud800z"), "y z");
    strictEqual(cleanComment("😀"), "😀");
  });

  // Catches an empty comment sent as "" instead of none.
  it("gives nothing for an empty or blank comment", () => {
    strictEqual(cleanComment(""), undefined);
    strictEqual(cleanComment(" \n\t "), undefined);
    strictEqual(cleanComment(42), undefined);
    strictEqual(cleanComment(undefined), undefined);
  });

  // Catches a cut by characters (129 fit in 256) or one through the middle of a letter.
  it("cuts at 256 bytes on a character boundary", () => {
    const cut = cleanComment("я".repeat(127) + "aя");
    strictEqual(cut, "я".repeat(127) + "a");
    strictEqual(bytes(cut!), 255);
  });

  // Catches 300 bytes passed through whole.
  it("cuts 300 ASCII bytes to 256", () => {
    strictEqual(cleanComment("x".repeat(300)), "x".repeat(256));
  });

  // Catches a trim done only before the cut, leaving a trailing space at the edge.
  it("trims a space the cut leaves at the end", () => {
    strictEqual(cleanComment("x".repeat(255) + " yz"), "x".repeat(255));
  });
});

describe("a comment on an imported rule", () => {
  // Catches a .mtrickle name dropped by the schema, or mapped uncleaned.
  it("takes a .mtrickle rule's name, cleaned", () => {
    const [group] = groupsFromFile(
      "export.mtrickle",
      fileWith([{ id: "37e03b4c", name: "Meta\nCDN", type: "domain", rule: "a.ru", enable: true }]),
    );
    strictEqual(group.rules[0].comment, "Meta CDN");
  });

  // Catches a 300-byte name kept whole, which the daemon refuses on Save.
  it("cuts a long .mtrickle name to 256 bytes", () => {
    const [group] = groupsFromFile(
      "export.mtrickle",
      fileWith([{ id: "37e03b4c", name: "n".repeat(300), type: "domain", rule: "a.ru" }]),
    );
    strictEqual(group.rules[0].comment, "n".repeat(256));
  });

  // Catches a name that only repeats the pattern turned into a comment.
  it("drops a .mtrickle name that equals the pattern", () => {
    const [group] = groupsFromFile(
      "export.mtrickle",
      fileWith([
        { id: "37e03b4c", name: "a.ru", type: "domain", rule: "a.ru" },
        { id: "37e03b4d", name: " ", type: "domain", rule: "b.ru" },
      ]),
    );
    strictEqual(group.rules[0].comment, undefined);
    strictEqual(group.rules[1].comment, undefined);
  });

  // Catches a .firc comment imported uncleaned, or blank kept as "".
  it("cleans a .firc rule's comment", () => {
    const [group] = groupsFromFile(
      "config.firc",
      fileWith([
        { id: "37e03b4c", comment: "  x\ny ", type: "domain", rule: "a.ru" },
        { id: "37e03b4d", comment: "   ", type: "domain", rule: "b.ru" },
        { id: "37e03b4e", comment: 7, type: "domain", rule: "c.ru" },
      ]),
    );
    strictEqual(group.rules[0].comment, "x y");
    strictEqual(group.rules[1].comment, undefined);
    strictEqual(group.rules[2].comment, undefined);
  });

  // Catches firc's own comment dropped because it repeats the pattern.
  it("keeps a .firc comment that equals the pattern", () => {
    const [group] = groupsFromFile(
      "config.firc",
      fileWith([{ id: "37e03b4c", comment: "a.ru", type: "domain", rule: "a.ru" }]),
    );
    strictEqual(group.rules[0].comment, "a.ru");
  });

  // Catches the name mapping applied to firc's own file.
  it("never takes a .firc rule's name", () => {
    const [group] = groupsFromFile(
      "config.firc",
      fileWith([{ id: "37e03b4c", name: "old", type: "domain", rule: "a.ru" }]),
    );
    strictEqual(group.rules[0].comment, undefined);
  });
});
