export type MockIfaceState = { state: "alive" | "dead" | "unknown"; since: number; error: string };

type MockGroup = { interface: string | string[]; enable?: boolean };

export const listOf = (group: MockGroup): string[] =>
  Array.isArray(group.interface) ? group.interface : [group.interface];

export function activeOf(group: MockGroup, at: number | undefined): string {
  const names = listOf(group);
  if (group.enable === false) return names[0];
  return names[at ?? 0] ?? names[0];
}

export function moveUp(
  group: MockGroup | undefined,
  at: number | undefined,
  states: Record<string, MockIfaceState>,
): { status: number; error?: string } {
  if (!group) return { status: 404, error: "group not exist" };
  const names = listOf(group);
  if (names.length < 2) return { status: 400, error: "the group names one interface" };
  if (group.enable === false) return { status: 409, error: "the group is not routed" };
  if ((at ?? 0) === 0) return { status: 200 };
  if (states[names[0]]?.state !== "alive") {
    return { status: 409, error: `${names[0]} is not alive` };
  }
  return { status: 200 };
}
