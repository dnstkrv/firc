import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import {
  inboundLook,
  inboundPortsByNode,
  inboundRefusal,
  nextInboundPort,
} from "../../src/modules/tunnels/inbounds.ts";
import type { TunnelInbound } from "../../src/types.ts";

const row = (port: number, extra: Partial<TunnelInbound> = {}): TunnelInbound => ({
  port,
  listen: "br0",
  node: "0000000a:A",
  user: "",
  password: "",
  ...extra,
});
const id = (k: string) => k;
const LINK = ["br0", "br1"];

describe("inboundRefusal", () => {
  // Catches a check that refuses valid distinct ports on different listens.
  it("accepts a clean list", () => {
    assert.strictEqual(
      inboundRefusal([row(1080), row(1081, { listen: "br1" })], [], LINK, id),
      null,
    );
  });

  // Catches a mirror that compares the listen too, which the daemon does not.
  it("refuses the same port twice in one tunnel even on different listens", () => {
    const got = inboundRefusal([row(1080), row(1080, { listen: "br1" })], [], LINK, id);
    assert.deepStrictEqual(got, {
      index: 1,
      field: "inbounds[1].port",
      text: "used twice in this tunnel",
    });
  });

  // Catches a cross-tunnel check that ignores the listen or never looks at other tunnels.
  it("refuses the same listen and port taken by another tunnel", () => {
    const other = [{ inbounds: [row(1080)] }];
    const got = inboundRefusal([row(1080)], other, LINK, id);
    assert.strictEqual(got?.field, "inbounds[0].port");
    assert.strictEqual(inboundRefusal([row(1080, { listen: "br1" })], other, LINK, id), null);
  });

  // Catches an off-by-one on either end of the reserved range.
  it("refuses 3600 to 3699 and keeps 3599 and 3700", () => {
    assert.strictEqual(inboundRefusal([row(3600)], [], LINK, id)?.field, "inbounds[0].port");
    assert.strictEqual(inboundRefusal([row(3699)], [], LINK, id)?.field, "inbounds[0].port");
    assert.strictEqual(inboundRefusal([row(3599)], [], LINK, id), null);
    assert.strictEqual(inboundRefusal([row(3700)], [], LINK, id), null);
  });

  // Catches a missing bound, an inclusive-exclusive slip, or integers not required.
  it("refuses port 53 and ports outside 1 to 65535", () => {
    for (const p of [53, 0, 65536, 1.5]) {
      assert.strictEqual(
        inboundRefusal([row(p)], [], LINK, id)?.field,
        "inbounds[0].port",
        String(p),
      );
    }
    assert.strictEqual(inboundRefusal([row(65535)], [], LINK, id), null);
    assert.strictEqual(inboundRefusal([row(1)], [], LINK, id), null);
  });

  // Catches a check of only one direction of both-or-neither.
  it("refuses a user without a password and a password without a user", () => {
    const a = inboundRefusal([row(1080, { user: "u" })], [], LINK, id);
    assert.deepStrictEqual(a, {
      index: 0,
      field: "inbounds[0].user",
      text: "user and password: both or neither",
    });
    const b = inboundRefusal([row(1080, { password: "p" })], [], LINK, id);
    assert.strictEqual(b?.field, "inbounds[0].user");
  });

  // Catches a colon ban applied to the password or not to the user.
  it("refuses a colon in the user and keeps one in the password", () => {
    assert.strictEqual(
      inboundRefusal([row(1080, { user: "a:b", password: "p" })], [], LINK, id)?.field,
      "inbounds[0].user",
    );
    assert.strictEqual(
      inboundRefusal([row(1080, { user: "ab", password: "p:q" })], [], LINK, id),
      null,
    );
  });

  // Catches a listen accepted though app.link lacks it, or a text without the name.
  it("refuses a listen outside app.link and names it", () => {
    const got = inboundRefusal([row(1080, { listen: "wg0" })], [], LINK, (k) => k);
    assert.strictEqual(got?.field, "inbounds[0].listen");
    assert.strictEqual(got?.text, "wg0 is not in the LAN list (app.link)");
  });

  // Catches every listen refused while app.link is not loaded yet.
  it("does not judge the listen while app.link is unknown", () => {
    assert.strictEqual(inboundRefusal([row(1080, { listen: "wg0" })], [], [], id), null);
  });

  // Catches a row saved with no node.
  it("refuses an empty node", () => {
    assert.strictEqual(
      inboundRefusal([row(1080, { node: "" })], [], LINK, id)?.field,
      "inbounds[0].node",
    );
  });

  // Catches a cap off by one in either direction.
  it("refuses the 17th inbound and accepts the 16th", () => {
    const sixteen = Array.from({ length: 16 }, (_, i) => row(2000 + i));
    assert.strictEqual(inboundRefusal(sixteen, [], LINK, id), null);
    const got = inboundRefusal([...sixteen, row(2100)], [], LINK, id);
    assert.strictEqual(got?.index, 16);
  });
});

describe("inboundPortsByNode", () => {
  // Catches ports attached to the wrong node or sorted away from row order.
  it("groups ports by node key in row order", () => {
    const tn = { inbounds: [row(1081, { node: "x:B" }), row(1080), row(1082, { node: "x:B" })] };
    assert.deepStrictEqual(
      [...inboundPortsByNode(tn)],
      [
        ["x:B", [1081, 1082]],
        ["0000000a:A", [1080]],
      ],
    );
  });
});

describe("nextInboundPort", () => {
  // Catches a new row that reuses a port already in the list.
  it("takes the first free port from 1080", () => {
    assert.strictEqual(nextInboundPort([]), 1080);
    assert.strictEqual(nextInboundPort([row(1080), row(1081)]), 1082);
  });
});

describe("inboundLook", () => {
  // Catches a state mapped to the wrong tone or a text that drops the interface name.
  it("maps each state to its text and tone", () => {
    assert.deepStrictEqual(inboundLook("up", "br0", id), { text: "listens", tone: "green" });
    assert.deepStrictEqual(inboundLook("busy", "br0", id), { text: "port is busy", tone: "red" });
    assert.deepStrictEqual(inboundLook("no-node", "br0", id), {
      text: "node is gone",
      tone: "orange",
    });
    assert.deepStrictEqual(inboundLook("no-address", "br1", id), {
      text: "br1 has no IPv4",
      tone: "orange",
    });
    assert.deepStrictEqual(inboundLook("not-lan", "br1", id), {
      text: "br1 is not in the LAN list",
      tone: "orange",
    });
    assert.strictEqual(inboundLook("starting", "br0", id).tone, "grey");
    assert.deepStrictEqual(inboundLook("off", "br0", id), { text: "tunnel is off", tone: "grey" });
  });
});
