import { t } from "../../data/locale.svelte";

import type { SettingValue } from "./settings";

export type Control =
  | { kind: "text"; placeholder?: () => string; width?: string }
  | { kind: "number"; unit?: () => string; width?: string }
  | { kind: "switch"; invert?: boolean; caption?: string }
  | { kind: "tags" };

export type Field = { key: string; label: () => string; control: Control };
export type Row = { label: () => string; hint: () => string; fields: Field[]; joiner?: string };
export type Section = { id: string; title: () => string; rows: Row[] };

const row = (label: () => string, hint: () => string, fields: Field[], joiner?: string): Row => ({
  label,
  hint,
  fields,
  joiner,
});

export const SECTIONS: Section[] = [
  {
    id: "dns",
    title: () => t("DNS proxy"),
    rows: [
      row(
        () => t("Upstream DNS"),
        () => t("Where the daemon forwards client queries"),
        [
          {
            key: "app.dnsProxy.upstream.address",
            label: () => t("Upstream DNS"),
            control: { kind: "text" },
          },
          {
            key: "app.dnsProxy.upstream.port",
            label: () => t("Upstream DNS port"),
            control: { kind: "number", width: "5.5rem" },
          },
        ],
      ),
      row(
        () => t("Drop AAAA"),
        () => t("For group domains, when IPv6 is not routed"),
        [
          {
            key: "app.dnsProxy.disableDropAAAA",
            label: () => t("Drop AAAA"),
            control: { kind: "switch", invert: true },
          },
        ],
      ),
      row(
        () => t("TTL of answers outside the rules"),
        () =>
          t(
            "How soon a newly enabled rule takes effect for devices that already asked for the name; 0 keeps the upstream's TTL",
          ),
        [
          {
            key: "app.dnsProxy.unmatchedTtl",
            label: () => t("TTL of answers outside the rules"),
            control: { kind: "number", unit: () => t("s") },
          },
        ],
      ),
      row(
        () => t("Query timeout"),
        () => t("How long to wait for the upstream DNS"),
        [
          {
            key: "app.dnsProxy.timeout",
            label: () => t("Query timeout"),
            control: { kind: "number", unit: () => t("ms") },
          },
        ],
      ),
      row(
        () => t("Concurrent queries"),
        () => t("Past the limit new queries are dropped"),
        [
          {
            key: "app.dnsProxy.maxConcurrent",
            label: () => t("Concurrent queries"),
            control: { kind: "number" },
          },
        ],
      ),
      row(
        () => t("Idle connections"),
        () => t("Kept open to the upstream DNS in reserve"),
        [
          {
            key: "app.dnsProxy.maxIdleConns",
            label: () => t("Idle connections"),
            control: { kind: "number" },
          },
        ],
      ),
      row(
        () => t("Proxy address"),
        () => t("Where the daemon listens for DNS"),
        [
          {
            key: "app.dnsProxy.host.address",
            label: () => t("Proxy address"),
            control: { kind: "text" },
          },
          {
            key: "app.dnsProxy.host.port",
            label: () => t("Proxy port"),
            control: { kind: "number", width: "5.5rem" },
          },
        ],
      ),
      row(
        () => t("Port 53 interception"),
        () => t("Redirect clients' DNS to the proxy"),
        [
          {
            key: "app.dnsProxy.disableRemap53",
            label: () => t("Port 53 interception"),
            control: { kind: "switch", invert: true },
          },
        ],
      ),
    ],
  },
  {
    id: "pool",
    title: () => t("Address pool"),
    rows: [
      row(
        () => t("TTL ceiling"),
        () => t("No client keeps an answer longer; the quarantine counts from it too"),
        [
          {
            key: "app.addressPool.ttlClamp",
            label: () => t("TTL ceiling"),
            control: { kind: "number", unit: () => t("s") },
          },
        ],
      ),
      row(
        () => t("Domains in the pool, at most"),
        () => t("Past the limit a blackhole address is issued"),
        [
          {
            key: "app.addressPool.maxNames",
            label: () => t("Domains in the pool, at most"),
            control: { kind: "number" },
          },
        ],
      ),
      row(
        () => t("IPv4 pool"),
        () => t("Range and a group's chunk size"),
        [
          {
            key: "app.addressPool.v4.pool",
            label: () => t("IPv4 pool"),
            control: { kind: "text" },
          },
          {
            key: "app.addressPool.v4.chunk",
            label: () => t("IPv4 pool chunk"),
            control: { kind: "number", width: "4.5rem" },
          },
        ],
        "/",
      ),
      row(
        () => t("IPv6 pool"),
        () => t("Empty means the generated ULA /48"),
        [
          {
            key: "app.addressPool.v6.pool",
            label: () => t("IPv6 pool"),
            control: { kind: "text", placeholder: () => t("auto") },
          },
          {
            key: "app.addressPool.v6.chunk",
            label: () => t("IPv6 pool chunk"),
            control: { kind: "number", width: "4.5rem" },
          },
        ],
        "/",
      ),
    ],
  },
  {
    id: "netfilter",
    title: () => t("Netfilter"),
    rows: [
      row(
        () => t("Address families"),
        () => t("Which ones kernel rules are written for"),
        [
          {
            key: "app.netfilter.disableIPv4",
            label: () => t("IPv4 rules"),
            control: { kind: "switch", invert: true, caption: "IPv4" },
          },
          {
            key: "app.netfilter.disableIPv6",
            label: () => t("IPv6 rules"),
            control: { kind: "switch", invert: true, caption: "IPv6" },
          },
        ],
      ),
      row(
        () => t("LAN interfaces"),
        () => t("Which interfaces traffic is intercepted on"),
        [{ key: "app.link", label: () => t("LAN interfaces"), control: { kind: "tags" } }],
      ),
      row(
        () => t("iptables chain prefix"),
        () => t("Every chain firc writes starts with it"),
        [
          {
            key: "app.netfilter.iptables.chainPrefix",
            label: () => t("iptables chain prefix"),
            control: { kind: "text" },
          },
        ],
      ),
      row(
        () => t("Starting mark and table index"),
        () => t("Change only if it clashes with other software"),
        [
          {
            key: "app.netfilter.startMarkTableIndex",
            label: () => t("Starting mark and table index"),
            control: { kind: "text" },
          },
        ],
      ),
    ],
  },
  {
    id: "check",
    title: () => t("Interface check"),
    rows: [
      row(
        () => t("Check URL"),
        () => t("A GET through each interface of a list; only a 204 answer counts as alive"),
        [
          {
            key: "app.check.url",
            label: () => t("Check URL"),
            control: { kind: "text", width: "22rem" },
          },
        ],
      ),
      row(
        () => t("Check interval"),
        () => t("Seconds between two checks of one interface, 10 to 3600"),
        [
          {
            key: "app.check.interval",
            label: () => t("Check interval"),
            control: { kind: "number", unit: () => t("s") },
          },
        ],
      ),
      row(
        () => t("Check timeout"),
        () => t("Seconds a check may take, 1 to 30"),
        [
          {
            key: "app.check.timeout",
            label: () => t("Check timeout"),
            control: { kind: "number", unit: () => t("s") },
          },
        ],
      ),
    ],
  },
  {
    id: "webui",
    title: () => t("WebUI"),
    rows: [
      row(
        () => t("WebUI address"),
        () => t("Where this page is served"),
        [
          {
            key: "app.httpWeb.host.address",
            label: () => t("WebUI address"),
            control: { kind: "text" },
          },
          {
            key: "app.httpWeb.host.port",
            label: () => t("WebUI port"),
            control: { kind: "number", width: "5.5rem" },
          },
        ],
      ),
    ],
  },
  {
    id: "updates",
    title: () => t("Updates"),
    rows: [
      row(
        () => t("Check for updates daily"),
        () => t("Asks GitHub once a day; off by default"),
        [
          {
            key: "app.update.check",
            label: () => t("Check for updates daily"),
            control: { kind: "switch" },
          },
        ],
      ),
    ],
  },
];

export const FIELDS: Record<string, Field> = Object.fromEntries(
  SECTIONS.flatMap((s) => s.rows.flatMap((r) => r.fields)).map((f) => [f.key, f]),
);

export function formatValue(key: string, value: SettingValue | undefined): string {
  if (value === undefined || value === null) return "";
  const control = FIELDS[key]?.control;
  if (typeof value === "boolean") {
    const shown = control?.kind === "switch" && control.invert ? !value : value;
    return shown ? t("on") : t("off");
  }
  if (Array.isArray(value)) return value.join(", ");
  if (value === "" && key === "app.addressPool.v6.pool") return t("auto");
  const unit = control?.kind === "number" && control.unit ? ` ${control.unit()}` : "";
  return `${value}${unit}`;
}
