export function modifierLabel(platform: string): string {
  return /mac|iphone|ipad|ipod/i.test(platform) ? "⌘" : "Ctrl";
}

type PlatformNavigator = Navigator & { userAgentData?: { platform?: string } };

const nav = globalThis.navigator as PlatformNavigator | undefined;

export const MOD = modifierLabel(nav?.userAgentData?.platform || nav?.platform || "");
