export const COMMENT_MAX_BYTES = 256;

const REFUSED = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]|\p{Cs}/gu;

export function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

export function cutToBytes(value: string, max = COMMENT_MAX_BYTES): string {
  let used = 0;
  let end = 0;
  for (const ch of value) {
    const size = utf8Length(ch);
    if (used + size > max) break;
    used += size;
    end += ch.length;
  }
  return value.slice(0, end);
}

export function cleanComment(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const flat = raw.replace(REFUSED, " ").replace(/^ +| +$/g, "");
  const cut = cutToBytes(flat).replace(/ +$/, "");
  return cut === "" ? undefined : cut;
}
