import type { DeviceSelector, Rule } from "../../types";

export type OverlapKind = "shadowed" | "split";

export type RuleOverlap = {
  kind: OverlapKind;
  groupId: string;
  groupName: string;
  ruleId: string;
};

export type OverlapGroup = {
  id: string;
  name: string;
  enable: boolean;
  devices: DeviceSelector;
  rules: Rule[];
};

export function ruleKey(rule: Pick<Rule, "type" | "rule" | "proto" | "ports">): string {
  return `${rule.type}:${rule.rule}:${rule.proto ?? ""}:${rule.ports ?? ""}`;
}

const entries = (list: string[]) => new Set(list.map((e) => e.trim()).filter(Boolean));

export function admitsEveryDeviceOf(upper: DeviceSelector, lower: DeviceSelector): boolean {
  const upperAllow = entries(upper.allow);
  const upperDeny = entries(upper.deny);
  if (upperAllow.size === 0 && upperDeny.size === 0) return true;
  const lowerAllow = entries(lower.allow);
  const lowerDeny = entries(lower.deny);
  if (upperAllow.size !== lowerAllow.size) return false;
  for (const e of upperAllow) if (!lowerAllow.has(e)) return false;
  for (const e of upperDeny) if (!lowerDeny.has(e)) return false;
  return true;
}

export function computeOverlaps(groups: OverlapGroup[]): Map<string, RuleOverlap> {
  const earlier = new Map<string, { group: OverlapGroup; rule: Rule }[]>();
  const overlaps = new Map<string, RuleOverlap>();
  for (const group of groups) {
    for (const rule of group.rules) {
      if (!rule.rule.trim()) continue;
      const key = ruleKey(rule);
      let before = earlier.get(key);
      if (!before) {
        before = [];
        earlier.set(key, before);
      }
      if (before.length > 0) {
        const shadow = before.find((e) => admitsEveryDeviceOf(e.group.devices, group.devices));
        const named = shadow ?? before[0];
        overlaps.set(rule.id, {
          kind: shadow ? "shadowed" : "split",
          groupId: named.group.id,
          groupName: named.group.name,
          ruleId: named.rule.id,
        });
      }
      if (group.enable && rule.enable) before.push({ group, rule });
    }
  }
  return overlaps;
}
