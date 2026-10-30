import type { Rule } from "../../types";
import { counted } from "../../utils/plural";

type WithId = { id: string };

/* A new array either way: a `$state` array only changes when reassigned. */
export function toggleId(ids: readonly string[], id: string): string[] {
  return ids.includes(id) ? ids.filter((value) => value !== id) : [...ids, id];
}

export function selectedInOrder(ids: readonly string[], groups: readonly WithId[]): string[] {
  if (!ids.length) return [];
  const wanted = new Set(ids);
  return groups.filter((group) => wanted.has(group.id)).map((group) => group.id);
}

export function selectableIds(
  groups: readonly WithId[],
  searchActive: boolean,
  visible: { has(index: number): boolean },
): string[] {
  return groups.filter((_, index) => !searchActive || visible.has(index)).map((group) => group.id);
}

export function rangeIds(
  shown: readonly string[],
  anchor: string | null,
  target: string,
): string[] | null {
  const from = anchor === null ? -1 : shown.indexOf(anchor);
  const to = shown.indexOf(target);
  if (from < 0 || to < 0) return null;
  return shown.slice(Math.min(from, to), Math.max(from, to) + 1);
}

export function moveBlock<T extends WithId>(
  items: readonly T[],
  moving: ReadonlySet<string>,
  slotId: string,
  insert: "before" | "after",
): T[] {
  const slot = items.findIndex((item) => item.id === slotId);
  if (slot < 0) return [...items];
  const stays = (item: T) => !moving.has(item.id);
  const block = items.filter((item) => moving.has(item.id));
  const rest = items.filter(stays);
  let at: number;
  if (stays(items[slot])) {
    at = rest.indexOf(items[slot]) + (insert === "after" ? 1 : 0);
  } else if (insert === "after") {
    const next = items.slice(slot + 1).find(stays);
    at = next ? rest.indexOf(next) : rest.length;
  } else {
    const prev = items.slice(0, slot).filter(stays).pop();
    at = prev ? rest.indexOf(prev) + 1 : 0;
  }
  return [...rest.slice(0, at), ...block, ...rest.slice(at)];
}

const DOMAIN_TYPES = new Set(["namespace", "wildcard", "domain"]);

export function domainLines(
  groups: readonly { rules: readonly Pick<Rule, "rule" | "type" | "enable">[] }[],
): string[] {
  const seen = new Set<string>();
  for (const group of groups) {
    for (const rule of group.rules) {
      const text = rule.rule.trim();
      if (text && rule.enable && DOMAIN_TYPES.has(rule.type)) seen.add(text);
    }
  }
  return [...seen];
}

export function selectionCountText(n: number, locale: string, t: (key: string) => string): string {
  return counted(
    n,
    locale,
    t("{n} group selected"),
    t("{n} groups selected (2-4)"),
    t("{n} groups selected"),
  );
}
