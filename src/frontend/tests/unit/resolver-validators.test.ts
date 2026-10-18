import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import { resolverAddrProblem, resolverListProblem } from "../../src/utils/resolver-validators.ts";

describe("resolverAddrProblem", () => {
  it("accepts each shape the daemon accepts", () => {
    for (const ok of [
      "9.9.9.9",
      "9.9.9.9:5353",
      "2620:fe::fe",
      "[2620:fe::fe]:853",
      "[2620:fe::fe]",
      "2620:fe::fe:53",
      "9.9.9.9:65535",
      "9.9.9.9:1",
      "126.255.255.255",
      "128.0.0.1",
      "0.0.0.1",
      "::2",
    ]) {
      assert.strictEqual(resolverAddrProblem(ok), null, ok);
    }
  });

  it("refuses what is not an address literal", () => {
    for (const bad of [
      "",
      "dns.google",
      "9.9.9",
      "9.9.9.9:",
      "[9.9.9.9]",
      "[9.9.9.9]:53",
      "[2620:fe::fe",
      "2620:fe::fe]",
      "9.9.9.9:53x",
      " 9.9.9.9",
      "9.9.9.9 ",
      "[2620:fe::fe]53",
    ]) {
      assert.strictEqual(resolverAddrProblem(bad), "syntax", bad);
    }
  });

  it("refuses a port outside 1..65535", () => {
    for (const bad of [
      "9.9.9.9:0",
      "9.9.9.9:65536",
      "9.9.9.9:+53",
      "9.9.9.9:053535",
      "[2620:fe::fe]:0",
      "9.9.9.9:-1",
      "9.9.9.9:+",
      "[::1]:-",
    ]) {
      assert.strictEqual(resolverAddrProblem(bad), "port", bad);
    }
  });

  it("refuses sinks and IPv4-mapped addresses", () => {
    for (const bad of [
      "0.0.0.0",
      "127.0.0.1",
      "127.255.255.254:53",
      "::",
      "::1",
      "[::1]:53",
      "[::]:5353",
    ]) {
      assert.strictEqual(resolverAddrProblem(bad), "sink", bad);
    }
    assert.strictEqual(resolverAddrProblem("::ffff:127.0.0.1"), "mapped");
    assert.strictEqual(resolverAddrProblem("::ffff:9.9.9.9"), "mapped");
  });
});

describe("resolverListProblem", () => {
  // Catches a comma list refused, blanks around an entry kept, or four entries counted as too many.
  it("accepts one to four servers separated by commas", () => {
    for (const ok of [
      "1.1.1.1, 9.9.9.9",
      "[2606:4700::1111]:53,1.1.1.1:5353",
      "\t9.9.9.9 ",
      "1.1.1.1,1.0.0.1, 9.9.9.9 ,2620:fe::fe",
      "9.9.9.9, 9.9.9.9:5353",
    ]) {
      assert.strictEqual(resolverListProblem(ok), null, ok);
    }
  });

  // Catches a fifth server, an empty entry or a twin let through, the same cases the daemon refuses.
  it("refuses a fifth server, an empty entry and a twin", () => {
    assert.deepStrictEqual(resolverListProblem("1.1.1.1,1.0.0.1,9.9.9.9,8.8.8.8,8.8.4.4"), {
      problem: "too-many",
      entry: "",
    });
    for (const bad of ["1.1.1.1,,9.9.9.9", "1.1.1.1,", ",1.1.1.1", "1.1.1.1, ,9.9.9.9", " ", ""]) {
      assert.deepStrictEqual(resolverListProblem(bad), { problem: "empty", entry: "" }, bad);
    }
    assert.deepStrictEqual(resolverListProblem("9.9.9.9, 1.1.1.1, 9.9.9.9:53"), {
      problem: "duplicate",
      entry: "9.9.9.9:53",
    });
    assert.deepStrictEqual(resolverListProblem("[2620:fe::fe]:53, 2620:fe::fe"), {
      problem: "duplicate",
      entry: "2620:fe::fe",
    });
  });

  // Catches a bad entry after a good one accepted, or the problem pinned on the wrong entry.
  it("names the entry that is not a server", () => {
    assert.deepStrictEqual(resolverListProblem("1.1.1.1, dns.google"), {
      problem: "syntax",
      entry: "dns.google",
    });
    assert.deepStrictEqual(resolverListProblem("127.0.0.1 ,1.1.1.1"), {
      problem: "sink",
      entry: "127.0.0.1",
    });
    assert.deepStrictEqual(resolverListProblem("1.1.1.1,9.9.9.9:0"), {
      problem: "port",
      entry: "9.9.9.9:0",
    });
    assert.deepStrictEqual(resolverListProblem("1.1.1.1 9.9.9.9"), {
      problem: "syntax",
      entry: "1.1.1.1 9.9.9.9",
    });
    assert.deepStrictEqual(resolverListProblem("9.9.9.9,::ffff:9.9.9.9"), {
      problem: "mapped",
      entry: "::ffff:9.9.9.9",
    });
  });
});
