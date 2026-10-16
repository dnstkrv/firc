import { parseV4, parseV6 } from "./device-validators";

function isValidNamePattern(pattern: string, allowGlob: boolean): boolean {
  const folded = pattern.replace(/^[ \t]+|[ \t]+$/g, "").replace(/\.$/, "");
  if (folded === "") return false;
  if (folded.length > 253) return false;
  if (folded.startsWith(".")) return false;
  const labels = folded.split(".");
  const label = allowGlob ? /^[a-zA-Z0-9\-_*?]+$/ : /^[a-zA-Z0-9\-_]+$/;
  return labels.every((l) => l.length > 0 && l.length <= 63 && label.test(l));
}

export function isValidWildcard(pattern: string): boolean {
  return isValidNamePattern(pattern, true);
}

export function isValidDomain(pattern: string): boolean {
  return isValidNamePattern(pattern, false);
}

export function isValidNamespace(pattern: string): boolean {
  return isValidDomain(pattern);
}

export function isValidSubnet(pattern: string): boolean {
  const slash = pattern.indexOf("/");
  const addr = slash === -1 ? pattern : pattern.slice(0, slash);
  if (parseV4(addr) === null) return false;
  if (slash === -1) return true;
  const rest = pattern.slice(slash + 1);
  if (!/^[0-9]+$/.test(rest)) return false;
  return Number(rest) <= 32;
}

function isValidIPv6(ip: string): boolean {
  return parseV6(ip) !== null;
}

export function isValidSubnet6(pattern: string): boolean {
  const parts = pattern.split("/");
  if (parts.length === 1) {
    return isValidIPv6(parts[0]);
  }

  if (parts.length !== 2) return false;

  if (!/^[0-9]+$/.test(parts[1])) return false;
  if (Number(parts[1]) > 128) return false;

  return isValidIPv6(parts[0]);
}

const PCRE2_ONLY = /\(\?[>(]|\(\?[a-zA-Z-]+[):]|[*+?}]\+|\\[AzZKGhHRNX]|\\k<|\(\?R\)|\(\?[0-9]/;

export function isValidRegex(pattern: string): boolean {
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return PCRE2_ONLY.test(pattern);
  }
}

export const PORTS_MAX_SLOTS = 15;

export type PortProblem = "syntax" | "range" | "order";
export type PortToken = { slots: number } | { problem: PortProblem };

export function portToken(token: string): PortToken {
  const bounds = /^([0-9]{1,5})(?:-([0-9]{1,5}))?$/.exec(token);
  if (!bounds) return { problem: "syntax" };
  const from = Number(bounds[1]);
  const to = bounds[2] === undefined ? from : Number(bounds[2]);
  if (from < 1 || to < 1 || from > 65535 || to > 65535) return { problem: "range" };
  if (from > to) return { problem: "order" };
  return { slots: from === to ? 1 : 2 };
}

export function splitPorts(text: string): string[] {
  return text
    .split(",")
    .map((token) => token.trim())
    .filter((token) => token !== "");
}

export function joinPorts(tokens: string[]): string {
  return tokens.join(",");
}

export function portsSlots(tokens: string[]): number {
  return tokens.reduce((sum, token) => {
    const parsed = portToken(token);
    return sum + ("slots" in parsed ? parsed.slots : 0);
  }, 0);
}

export function isValidPorts(ports: string): boolean {
  if (ports === "") return true;
  const tokens = ports.split(",");
  return (
    tokens.every((token) => "slots" in portToken(token)) && portsSlots(tokens) <= PORTS_MAX_SLOTS
  );
}

export const VALIDATOP_MAP: Record<string, (pattern: string) => boolean> = {
  regex: isValidRegex,
  wildcard: isValidWildcard,
  domain: isValidDomain,
  namespace: isValidNamespace,
  subnet: isValidSubnet,
  subnet6: isValidSubnet6,
};
