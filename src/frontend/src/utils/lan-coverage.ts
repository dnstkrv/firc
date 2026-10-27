import type { DeviceSelector } from "../types";
import {
  foldManual,
  hostRows,
  rowState,
  selectorMode,
  splitSelector,
  type Host,
  type PickerPolicy,
} from "./device-picker";

export type Uncovered = { segment: string; groups: string[] };

type CoveringGroup = { name: string; enable: boolean; devices: DeviceSelector };

export function outsideLan(h: Host): boolean {
  return h.intercepted === false;
}

export function policyOutside(hosts: Host[], policy: string): number {
  const macs = new Set(hosts.filter((h) => h.policy === policy && outsideLan(h)).map((h) => h.mac));
  return macs.size;
}

export function uncoveredSegments(
  groups: CoveringGroup[],
  hosts: Host[],
  policies: PickerPolicy[],
  link: string[],
): Uncovered[] {
  const bySegment = new Map<string, string[]>();
  for (const g of groups) {
    if (!g.enable) continue;
    const picked = foldManual(splitSelector(g.devices));
    const mode = selectorMode(picked);
    for (const row of hostRows(hosts, picked)) {
      const seg = row.segment;
      if (!outsideLan(row) || seg === undefined || link.includes(seg)) continue;
      if (!rowState(row, picked, policies, mode).on) continue;
      const names = bySegment.get(seg) ?? [];
      if (!names.includes(g.name)) names.push(g.name);
      bySegment.set(seg, names);
    }
  }
  return [...bySegment.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([segment, groups]) => ({ segment, groups }));
}
