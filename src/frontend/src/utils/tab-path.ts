const PATHS: Record<string, string> = {
  groups: "/groups",
  tunnels: "/tunnels",
  logs: "/journal",
  settings: "/settings",
};

export function pathOfTab(tab: string): string {
  return PATHS[tab] ?? PATHS.groups;
}

export function tabFromPath(path: string): string {
  return Object.keys(PATHS).find((tab) => PATHS[tab] === path) ?? "groups";
}
