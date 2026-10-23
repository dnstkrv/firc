export type CatalogSource = { id: string; url: string; names: string[] };
export type Catalog = {
  generated: string;
  fetchedAt: number;
  stale: boolean;
  sources: CatalogSource[];
};
export type CatalogRow = { name: string; source: string; url: string };
export type CatalogResult = { ok: true; data: Catalog } | { ok: false; error: string };

export const isUrlText = (text: string): boolean => text.includes("://");

export function searchCatalog(
  cat: { sources: CatalogSource[] },
  query: string,
  cap = 50,
): { rows: CatalogRow[]; more: number } {
  const q = query.trim().toLowerCase();
  if (!q) return { rows: [], more: 0 };
  const hits: { rank: number; row: CatalogRow }[] = [];
  for (const s of cat.sources) {
    for (const name of s.names) {
      const n = name.toLowerCase();
      if (!n.includes(q)) continue;
      const rank = n === q ? 0 : n.startsWith(q) ? 1 : 2;
      hits.push({ rank, row: { name, source: s.id, url: s.url.replace("{}", () => name) } });
    }
  }
  hits.sort((a, b) => a.rank - b.rank || a.row.name.length - b.row.name.length);
  return { rows: hits.slice(0, cap).map((h) => h.row), more: Math.max(0, hits.length - cap) };
}

let cached: Promise<CatalogResult> | null = null;

async function fetchCatalog(): Promise<CatalogResult> {
  try {
    const { fetcher } = await import("../../utils/fetcher");
    const data = await fetcher.get<Catalog>("/groups/list/catalog", { quiet: true });
    return { ok: true, data };
  } catch (e) {
    let error = "";
    try {
      const body = JSON.parse((e as Error).message);
      if (typeof body?.error === "string" && body.error) error = body.error;
    } catch {}
    return { ok: false, error };
  }
}

export function loadCatalog(): Promise<CatalogResult> {
  if (!cached) {
    const p = fetchCatalog();
    cached = p;
    p.then((r) => {
      if (!r.ok && cached === p) cached = null;
    });
  }
  return cached;
}
