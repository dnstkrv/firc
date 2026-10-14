import type { JournalEvent } from "./events.svelte";

type HeldClass = "debug" | "info" | "alert" | "traffic";

export const HELD: Record<HeldClass, number> = { debug: 512, info: 512, alert: 256, traffic: 4096 };

function classOf(e: JournalEvent): HeldClass {
  if (e.kind !== "log") return "traffic";
  if (e.level === "debug" || e.level === "info") return e.level;
  return "alert";
}

export function trimHeld(events: JournalEvent[]): JournalEvent[] {
  const seen: Record<HeldClass, number> = { debug: 0, info: 0, alert: 0, traffic: 0 };
  const keep = new Array<boolean>(events.length);
  let dropped = false;
  for (let i = events.length - 1; i >= 0; i--) {
    const c = classOf(events[i]);
    keep[i] = seen[c]++ < HELD[c];
    if (!keep[i]) dropped = true;
  }
  return dropped ? events.filter((_, i) => keep[i]) : events;
}
