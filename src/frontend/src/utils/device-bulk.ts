import type { DeviceSelector } from "../types";
import {
  flipPolicy,
  flipRow,
  hasAllow,
  hostRows,
  joinSelector,
  policyOn,
  policySide,
  rowState,
  selectorMode,
  setMode,
  splitSelector,
  writeKey,
  type Host,
  type HostRow,
  type Mode,
  type Picked,
  type PickerPolicy,
  type RowNote,
} from "./device-picker";

export type BulkMode = "keep" | Mode;

export type BulkEdits = { policies: Map<string, boolean>; macs: Map<string, boolean> };

export type Refusal =
  | { kind: "locked"; mac: string; note: RowNote }
  | { kind: "taken"; policy: string }
  | { kind: "nothing-chosen" };

export type BulkResult = { sel: DeviceSelector | null; refused: Refusal[] };

const canonical = (sel: DeviceSelector | undefined) =>
  JSON.stringify(joinSelector(splitSelector(sel)));

function startOf(sel: DeviceSelector | undefined, mode: BulkMode): { p: Picked; m: Mode } {
  const p = splitSelector(sel);
  const m = mode === "keep" ? selectorMode(p) : mode;
  return { p: m === selectorMode(p) ? p : setMode(p, m), m };
}

const sided = (row: HostRow, p: Picked): HostRow => ({ ...row, side: p.macs.get(row.mac) ?? null });

export function bulkRows(selectors: (DeviceSelector | undefined)[], hosts: Host[]): HostRow[] {
  const named = selectors.flatMap((sel) => [...splitSelector(sel).macs.keys()]);
  return hostRows(hosts, splitSelector(undefined), named);
}

export function applyBulk(
  sel: DeviceSelector | undefined,
  edits: BulkEdits,
  mode: BulkMode,
  policies: PickerPolicy[],
  hosts: Host[],
): BulkResult {
  let { p, m } = startOf(sel, mode);
  const refused: Refusal[] = [];
  for (const [id, target] of edits.policies) {
    if (policyOn(policySide(p, id, policies), m) === target) continue;
    if (writeKey(p, id, policies) === null) refused.push({ kind: "taken", policy: id });
    else p = flipPolicy(p, id, policies, m);
  }
  const rows = new Map(
    hostRows(hosts, splitSelector(undefined), edits.macs.keys()).map((r) => [r.mac, r]),
  );
  for (const [mac, target] of edits.macs) {
    const row = sided(rows.get(mac)!, p);
    const now = rowState(row, p, policies, m);
    if (now.on === target) continue;
    if (now.locked) refused.push({ kind: "locked", mac, note: now.note });
    else p = flipRow(p, row, policies, m);
  }
  if (m === "only" && !hasAllow(p))
    return { sel: null, refused: [...refused, { kind: "nothing-chosen" }] };
  const joined = joinSelector(p);
  return { sel: JSON.stringify(joined) === canonical(sel) ? null : joined, refused };
}

export function aggregate(
  selectors: (DeviceSelector | undefined)[],
  mode: BulkMode,
  policies: PickerPolicy[],
  hosts: Host[],
): { policies: Map<string, number>; macs: Map<string, number> } {
  const rows = bulkRows(selectors, hosts);
  const out = {
    policies: new Map(policies.map((pol) => [pol.name, 0])),
    macs: new Map(rows.map((r) => [r.mac, 0])),
  };
  for (const sel of selectors) {
    const { p, m } = startOf(sel, mode);
    for (const pol of policies)
      if (policyOn(policySide(p, pol.name, policies), m))
        out.policies.set(pol.name, out.policies.get(pol.name)! + 1);
    for (const row of rows)
      if (rowState(sided(row, p), p, policies, m).on)
        out.macs.set(row.mac, out.macs.get(row.mac)! + 1);
  }
  return out;
}

export function replaceWith(
  sel: DeviceSelector | undefined,
  value: DeviceSelector,
): DeviceSelector | null {
  if (canonical(sel) === canonical(value)) return null;
  return { allow: [...value.allow], deny: [...value.deny] };
}
