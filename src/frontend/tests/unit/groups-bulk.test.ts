import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import ru from "../../src/locales/ru.json" with { type: "json" };
import {
  moveBlock,
  rangeIds,
  selectableIds,
  selectedInOrder,
  selectionCountText,
  toggleId,
} from "../../src/modules/groups/selection.ts";
import { installSvelteRunesMocks } from "../mocks/setup-svelte-runes";

installSvelteRunesMocks();

const createMemoryStorage = () => {
  const store = new Map<string, string>();
  return {
    getItem(key: string) {
      return store.has(key) ? store.get(key)! : null;
    },
    setItem(key: string, value: string) {
      store.set(key, String(value));
    },
    removeItem(key: string) {
      store.delete(key);
    },
    clear() {
      store.clear();
    },
    key(index: number) {
      return Array.from(store.keys())[index] ?? null;
    },
    get length() {
      return store.size;
    },
  };
};

const patchGlobal = (key: string, value: unknown) => {
  const original = Object.getOwnPropertyDescriptor(globalThis, key);
  Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  return () => {
    if (original) {
      Object.defineProperty(globalThis, key, original);
      return;
    }
    delete (globalThis as any)[key];
  };
};

const restoreLocalStorage = patchGlobal("localStorage", createMemoryStorage());
type ProcessLike = { env?: unknown };
const processObj = (globalThis as unknown as { process?: ProcessLike }).process;
const originalProcessEnvDescriptor = processObj
  ? Object.getOwnPropertyDescriptor(processObj, "env")
  : undefined;
if (processObj) {
  Object.defineProperty(processObj, "env", {
    value: { NODE_ENV: "test" },
    configurable: true,
    writable: true,
  });
}
const { GroupsStore } = await import("../../src/modules/groups/groups.svelte");
const { answer, confirmation } = await import("../../src/utils/confirm.svelte");
if (processObj) {
  if (originalProcessEnvDescriptor) {
    Object.defineProperty(processObj, "env", originalProcessEnvDescriptor);
  } else {
    delete processObj.env;
  }
}
restoreLocalStorage();

const makeGroup = (id: string, iface = "wg0", enable = true) => ({
  id,
  name: `group-${id}`,
  interface: iface,
  enable,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules: [{ id: `r${id}`, enable: true, rule: `${id}.example.com`, type: "domain" }],
});

function seeded(groups: ReturnType<typeof makeGroup>[]) {
  const store = new GroupsStore();
  const cloned = structuredClone(groups);
  store.tracker.reset(cloned);
  store.resetListMetaBaseline(cloned);
  return store;
}

const ids = (groups: { id: string }[]) => groups.map((g) => g.id);

async function withConfirm<T>(ok: boolean, action: () => Promise<T>) {
  const asked: { title: string; items?: string[] }[] = [];
  const running = action();
  if (confirmation.current) {
    asked.push({ title: confirmation.current.title, items: confirmation.current.items });
    answer(ok);
  }
  return { result: await running, asked };
}

describe("the selection, as pure functions", () => {
  // Catches a second click leaving the group selected, or the toggle mutating its input array.
  it("toggles an id in and out without touching the input", () => {
    const start = ["a"];
    const added = toggleId(start, "b");
    assert.deepStrictEqual(added, ["a", "b"]);
    assert.deepStrictEqual(start, ["a"]);
    assert.deepStrictEqual(toggleId(added, "a"), ["b"]);
  });

  // Catches a deleted group still counted, or the order following the clicks instead of the page.
  it("keeps only groups that still exist, in page order", () => {
    const groups = [{ id: "a" }, { id: "b" }, { id: "c" }];
    assert.deepStrictEqual(selectedInOrder(["c", "gone", "a"], groups), ["a", "c"]);
    assert.deepStrictEqual(selectedInOrder([], groups), []);
  });

  // Catches Select all under a search picking hidden groups, or fewer than all without one.
  it("selects all groups, or only the ones a search shows", () => {
    const groups = [{ id: "a" }, { id: "b" }, { id: "c" }, { id: "d" }];
    const shown = new Map<number, null>([
      [1, null],
      [3, null],
    ]);
    assert.deepStrictEqual(selectableIds(groups, false, shown), ["a", "b", "c", "d"]);
    assert.deepStrictEqual(selectableIds(groups, true, shown), ["b", "d"]);
    assert.deepStrictEqual(selectableIds(groups, true, new Map()), []);
  });

  // Catches a range that drops an end, runs only one direction, or survives a missing anchor.
  it("takes the inclusive range between anchor and target among shown ids", () => {
    const shown = ["a", "b", "c", "d"];
    assert.deepStrictEqual(rangeIds(shown, "b", "d"), ["b", "c", "d"]);
    assert.deepStrictEqual(rangeIds(shown, "d", "b"), ["b", "c", "d"]);
    assert.deepStrictEqual(rangeIds(shown, "c", "c"), ["c"]);
    assert.strictEqual(rangeIds(shown, "x", "b"), null);
    assert.strictEqual(rangeIds(shown, null, "b"), null);
  });

  // Catches a block that splits, reorders its members, mutates the input, or moves onto itself.
  it("moves a block of ids together before or after a slot", () => {
    const x = ["a", "b", "c", "d", "e"].map((id) => ({ id }));
    const order = (items: { id: string }[]) => items.map((i) => i.id).join("");
    assert.strictEqual(order(moveBlock(x, new Set(["b", "d"]), "e", "after")), "acebd");
    assert.strictEqual(order(moveBlock(x, new Set(["b", "d"]), "a", "before")), "bdace");
    assert.strictEqual(order(moveBlock(x, new Set(["a", "e"]), "c", "after")), "bcaed");
    assert.strictEqual(order(moveBlock(x, new Set(["b"]), "zz", "before")), "abcde");
    assert.strictEqual(order(x), "abcde");
  });

  // Catches a drop on a moving group's edge that is ignored or lands at the wrong neighbour.
  it("resolves a slot on a moving group to its nearest non-moving neighbour", () => {
    const x = ["a", "b", "c", "d", "e"].map((id) => ({ id }));
    const order = (items: { id: string }[]) => items.map((i) => i.id).join("");
    assert.strictEqual(order(moveBlock(x, new Set(["b", "d"]), "d", "before")), "acbde");
    assert.strictEqual(order(moveBlock(x, new Set(["b", "d"]), "b", "after")), "abdce");
    assert.strictEqual(order(moveBlock(x, new Set(["b", "c", "e"]), "b", "after")), "abced");
    assert.strictEqual(order(moveBlock(x, new Set(["b", "d", "e"]), "e", "before")), "acbde");
    assert.strictEqual(order(moveBlock(x, new Set(["a", "c"]), "a", "before")), "acbde");
    assert.strictEqual(order(moveBlock(x, new Set(["c", "e"]), "e", "after")), "abdce");
    assert.strictEqual(order(x), "abcde");
  });

  // Catches the wrong Russian plural form in the count.
  it("counts the selection in Russian and English", () => {
    const tr = (key: string) => (ru as Record<string, string>)[key] ?? key;
    const en = (key: string) => key;
    const want: [number, string][] = [
      [1, "1 выбрана"],
      [3, "3 выбраны"],
      [5, "5 выбрано"],
      [11, "11 выбрано"],
      [21, "21 выбрана"],
      [24, "24 выбраны"],
    ];
    for (const [n, text] of want) assert.strictEqual(selectionCountText(n, "ru", tr), text);
    assert.strictEqual(selectionCountText(1, "en", en), "1 group selected");
    assert.strictEqual(selectionCountText(3, "en", en), "3 groups selected");
  });
});

describe("GroupsStore bulk actions", () => {
  // Catches a range that replaces when adding, moves the anchor, ignores clear, or ranges from a hidden anchor.
  it("selects a range from the anchor, replacing or adding", () => {
    const store = seeded(["a", "b", "c", "d", "e"].map((id) => makeGroup(id)));
    store.toggleSelected("a");
    store.toggleSelected("c");
    assert.deepStrictEqual(store.selection, ["a", "c"]);
    assert.strictEqual(store.anchorId, "c");
    store.selectRange("e", false);
    assert.deepStrictEqual(store.selection, ["c", "d", "e"]);
    store.selectRange("b", false);
    assert.deepStrictEqual(store.selection, ["b", "c"]);
    assert.strictEqual(store.anchorId, "c");
    store.toggleSelected("e");
    assert.deepStrictEqual(store.selection, ["b", "c", "e"]);
    assert.strictEqual(store.anchorId, "e");
    store.selectRange("a", true);
    assert.deepStrictEqual(store.selection, ["a", "b", "c", "d", "e"]);
    store.clearSelection();
    assert.strictEqual(store.anchorId, null);
    store.selectRange("b", false);
    assert.deepStrictEqual(store.selection, ["b"]);
    assert.strictEqual(store.anchorId, "b");
  });

  // Catches a range over groups the search hides, or a hidden anchor blocking the click.
  it("treats a hidden anchor as a plain toggle", () => {
    const store = seeded(["a", "b", "c", "d", "e"].map((id) => makeGroup(id)));
    store.toggleSelected("a");
    store.searchActive = true;
    store.visibilityMap = new Map([
      [1, null],
      [3, null],
    ]);
    store.selectRange("d", false);
    assert.deepStrictEqual(store.selection, ["a", "d"]);
    assert.strictEqual(store.anchorId, "d");
  });

  // Catches a selected drag moving one group, an unselected drag moving the selection, or hidden ones joining.
  it("dragging a selected group moves every selected group", () => {
    const store = seeded(["a", "b", "c", "d", "e"].map((id) => makeGroup(id)));
    store.toggleSelected("a");
    store.toggleSelected("c");
    const src = (id: string, i: number) => ({ group_id: id, group_index: i }) as any;
    store.handleGroupSlotDrop(src("c", 2), { group_index: 4, insert: "after" } as any);
    assert.deepStrictEqual(ids(store.data), ["b", "d", "e", "a", "c"]);
    assert.strictEqual(store.canSave, true);
    store.handleGroupSlotDrop(src("b", 0), { group_index: 2, insert: "after" } as any);
    assert.deepStrictEqual(ids(store.data), ["d", "e", "b", "a", "c"]);
    assert.deepStrictEqual(store.selection, ["a", "c"]);
  });

  // Catches a selected drop that keeps the order still bumping the data revision.
  it("a selected drop that keeps the order does not bump the revision", () => {
    const store = seeded(["a", "b", "c", "d", "e"].map((id) => makeGroup(id)));
    store.toggleSelected("a");
    store.toggleSelected("b");
    const src = (id: string, i: number) => ({ group_id: id, group_index: i }) as any;
    const revision = store.dataRevision;
    store.handleGroupSlotDrop(src("b", 1), { group_index: 0, insert: "after" } as any);
    assert.deepStrictEqual(ids(store.data), ["a", "b", "c", "d", "e"]);
    assert.strictEqual(store.dataRevision, revision);
    store.handleGroupSlotDrop(src("b", 1), { group_index: 3, insert: "after" } as any);
    assert.deepStrictEqual(ids(store.data), ["c", "d", "a", "b", "e"]);
    assert.strictEqual(store.dataRevision, revision + 1);
  });

  // Catches a hidden selected group being dragged along with the shown ones.
  it("drags only the selected groups a search shows", () => {
    const store = seeded(["a", "b", "c", "d", "e"].map((id) => makeGroup(id)));
    store.toggleSelected("a");
    store.toggleSelected("b");
    store.toggleSelected("c");
    store.searchActive = true;
    store.visibilityMap = new Map([
      [0, null],
      [2, null],
      [3, null],
    ]);
    assert.deepStrictEqual(store.draggedIds("a"), ["a", "c"]);
    assert.deepStrictEqual(store.draggedIds("d"), ["d"]);
  });

  // Catches selecting a group marking the form edited (Save lit).
  it("selecting is not an edit", () => {
    const store = seeded([makeGroup("a"), makeGroup("b")]);
    store.toggleSelected("a");
    assert.deepStrictEqual(store.selection, ["a"]);
    assert.strictEqual(store.isSelected("a"), true);
    assert.strictEqual(store.isSelected("b"), false);
    assert.strictEqual(store.canSave, false);
    store.clearSelection();
    assert.deepStrictEqual(store.selection, []);
  });

  // Catches the selection following the index instead of the id after a reorder.
  it("a selection survives a reorder", () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c")]);
    store.toggleSelected("a");
    store.changeGroupIndex(0, 2, "after");
    assert.deepStrictEqual(ids(store.data), ["b", "c", "a"]);
    assert.deepStrictEqual(store.selection, ["a"]);
  });

  // Catches the bulk interface skipping a selected group, touching another, or bypassing the tracker.
  it("sets the interface of every selected group as an edit", () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c")]);
    store.toggleSelected("a");
    store.toggleSelected("c");
    store.setSelectedChain(["nwg1"]);
    assert.deepStrictEqual(
      store.data.map((g) => g.interface),
      ["nwg1", "wg0", "nwg1"],
    );
    assert.strictEqual(store.canSave, true);
    assert.strictEqual(store.groupDirty(store.data[0]), true);
    assert.strictEqual(store.groupDirty(store.data[1]), false);
  });

  // Catches a chain written to an unselected group, or a list of one written as a list.
  it("sets a chain with backups on every selected group", () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c")]);
    store.toggleSelected("a");
    store.toggleSelected("c");
    store.setSelectedChain(["nwg0", "wg0"]);
    assert.deepStrictEqual(store.data[0].interface, ["nwg0", "wg0"]);
    assert.deepStrictEqual(store.data[2].interface, ["nwg0", "wg0"]);
    assert.strictEqual(store.data[1].interface, "wg0");
    assert.notStrictEqual(store.data[0].interface, store.data[2].interface);
    store.setSelectedChain(["nwg1"]);
    assert.strictEqual(store.data[0].interface, "nwg1");
  });

  // Catches the bulk DNS touching a blocking or unselected group, or sharing one object between groups.
  it("sets the DNS of the selected groups that do not block", () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c", "block")]);
    store.toggleSelected("a");
    store.toggleSelected("c");
    store.setSelectedResolve({ tunnel: false, server: "" });
    assert.deepStrictEqual(
      store.data.map((g) => g.resolve),
      [
        { tunnel: false, server: "" },
        { tunnel: true, server: "" },
        { tunnel: true, server: "" },
      ],
    );
    assert.strictEqual(store.groupDirty(store.data[0]), true);
    assert.strictEqual(store.groupDirty(store.data[1]), false);
    assert.strictEqual(store.groupDirty(store.data[2]), false);
    store.toggleSelected("b");
    const own = { tunnel: true, server: "1.1.1.1" };
    store.setSelectedResolve(own);
    assert.notStrictEqual(store.data[0].resolve, own);
    assert.notStrictEqual(store.data[0].resolve, store.data[1].resolve);
    assert.deepStrictEqual(store.data[1].resolve, own);
  });

  // Catches enable/disable applying the wrong value or to the wrong groups.
  it("enables and disables the selected groups", () => {
    const store = seeded([makeGroup("a"), makeGroup("b", "wg0", false), makeGroup("c")]);
    store.toggleSelected("b");
    store.toggleSelected("c");
    store.setSelectedEnable(true);
    assert.deepStrictEqual(
      store.data.map((g) => g.enable),
      [true, true, true],
    );
    store.setSelectedEnable(false);
    assert.deepStrictEqual(
      store.data.map((g) => g.enable),
      [true, false, false],
    );
  });

  // Catches bulk devices skipping a selected group, touching another, or bypassing the tracker.
  it("sets the devices of every selected group as an edit", () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c")]);
    store.toggleSelected("a");
    store.toggleSelected("c");
    store.setSelectedDevices(() => ({ allow: [], deny: ["mac:aa:00:00:00:00:02"] }));
    assert.deepStrictEqual(
      store.data.map((g) => g.devices),
      [
        { allow: [], deny: ["mac:aa:00:00:00:00:02"] },
        { allow: [], deny: [] },
        { allow: [], deny: ["mac:aa:00:00:00:00:02"] },
      ],
    );
    assert.strictEqual(store.canSave, true);
    assert.strictEqual(store.groupDirty(store.data[0]), true);
    assert.strictEqual(store.groupDirty(store.data[1]), false);
  });

  // Catches a null answer for a group assigned to it, so a group already at the value turns unsaved.
  it("a group already at the value is not marked unsaved", () => {
    const store = seeded([makeGroup("a"), makeGroup("b")]);
    store.toggleSelected("a");
    store.toggleSelected("b");
    store.setSelectedDevices((g) =>
      g.id === "a" ? null : { allow: ["mac:aa:00:00:00:00:01"], deny: [] },
    );
    assert.deepStrictEqual(store.data[0].devices, { allow: [], deny: [] });
    assert.strictEqual(store.groupDirty(store.data[0]), false);
    assert.deepStrictEqual(store.data[1].devices, { allow: ["mac:aa:00:00:00:00:01"], deny: [] });
    assert.strictEqual(store.groupDirty(store.data[1]), true);
  });

  // Catches Select all without a search missing a group.
  it("selects all groups without a search", async () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c")]);
    await store.selectAll();
    assert.deepStrictEqual(store.selection, ["a", "b", "c"]);
  });

  // Catches a cancelled confirm deleting, a confirm without the count, or deleted groups lingering selected.
  it("deletes the selected groups after one confirm", async () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c")]);
    store.toggleSelected("a");
    store.toggleSelected("c");

    const cancelled = await withConfirm(false, () => store.deleteSelected());
    assert.strictEqual(cancelled.asked.length, 1);
    assert.match(cancelled.asked[0].title, /\(2\)/);
    assert.deepStrictEqual(cancelled.asked[0].items, ["group-a", "group-c"]);
    assert.deepStrictEqual(ids(store.data), ["a", "b", "c"]);
    assert.deepStrictEqual(store.selection, ["a", "c"]);

    const accepted = await withConfirm(true, () => store.deleteSelected());
    assert.strictEqual(accepted.asked.length, 1);
    assert.deepStrictEqual(ids(store.data), ["b"]);
    assert.deepStrictEqual(store.selection, []);
    assert.strictEqual(store.canSave, true);
  });

  // Catches a group deleted from its own card staying selected.
  it("a group deleted from its card leaves the selection", async () => {
    const store = seeded([makeGroup("a"), makeGroup("b")]);
    store.toggleSelected("a");
    store.toggleSelected("b");
    await withConfirm(true, () => store.deleteGroup(0));
    assert.deepStrictEqual(store.selection, ["b"]);
    assert.deepStrictEqual(store.selectedIds, ["b"]);
  });
});

describe("a rule's comment in the store", () => {
  // Catches a comment edit not counted as unsaved, an empty string counted as none, or clearing to none leaving the group dirty.
  it("a comment makes the group unsaved and clearing it makes it clean again", () => {
    const store = seeded([makeGroup("a"), makeGroup("b")]);
    store.data[0].rules[0].comment = "Meta";
    assert.strictEqual(store.groupDirty(store.data[0]), true);
    assert.strictEqual(store.groupDirty(store.data[1]), false);
    store.data[0].rules[0].comment = "";
    assert.strictEqual(store.groupDirty(store.data[0]), true);
    store.data[0].rules[0].comment = undefined;
    assert.strictEqual(store.groupDirty(store.data[0]), false);
  });

  // Catches the comment made part of what makes two rules the same one.
  it("two rules differing only in their comment are duplicates", () => {
    const store = seeded([makeGroup("a"), makeGroup("b")]);
    store.data[1].rules[0].rule = "a.example.com";
    store.data[0].rules[0].comment = "one";
    store.data[1].rules[0].comment = "two";
    store.refreshDuplicateRuleIds();
    assert.strictEqual(store.ruleOverlap("ra"), undefined);
    const overlap = store.ruleOverlap("rb");
    assert.strictEqual(overlap?.kind, "shadowed");
    assert.ok(store.overlapText(overlap!).includes("group-a"));
  });
});

describe("the group's conflict menu", () => {
  // Catches a named earlier copy overwriting the kind of a rule the group already marks for itself.
  it("a marked rule keeps its own kind when a later rule names it", () => {
    const store = seeded([makeGroup("a"), makeGroup("b"), makeGroup("c")]);
    store.data[0].devices = { allow: ["192.168.1.5"], deny: [] };
    store.data[0].rules[0].rule = "x.example.com";
    store.data[2].rules = [
      { id: "c1", enable: true, rule: "x.example.com", type: "domain" },
      { id: "c2", enable: true, rule: "x.example.com", type: "domain" },
    ];
    store.refreshDuplicateRuleIds();
    assert.strictEqual(store.ruleOverlap("c1")?.kind, "split");
    assert.strictEqual(store.ruleOverlap("c2")?.kind, "shadowed");
    const byRule = new Map(store.getDuplicateConflictsForGroup("c").map((c) => [c.ruleId, c.kind]));
    assert.strictEqual(byRule.get("c1"), "split");
    assert.strictEqual(byRule.get("c2"), "shadowed");
    assert.strictEqual(byRule.get("ra"), "split");
  });
});
