<script lang="ts">
  import { onDestroy } from "svelte";

  import { t } from "../../data/locale.svelte";
  import { settings } from "./settings.svelte";

  import { fetcher } from "../../utils/fetcher";

  type AutolistRes = {
    enabled: boolean;
    running: boolean;
    whyOff?: string;
    failures: number;
    listed: number;
  };

  let state = $state<AutolistRes | null>(null);
  let timer: ReturnType<typeof setInterval> | undefined;

  async function load() {
    try {
      state = await fetcher.get<AutolistRes>("/system/autolist", { quiet: true });
    } catch {
      state = null;
    }
  }

  $effect(() => {
    void settings.saved["app.autolist.enabled"];
    void settings.saved["app.autolist.group"];
    void load();
  });
  timer = setInterval(() => void load(), 15000);
  onDestroy(() => clearInterval(timer));

  const text = $derived.by(() => {
    if (state === null || !state.enabled) return "";
    if (!state.running) return `${t("Not running")}: ${state.whyOff ?? ""}`;
    return t("Running: {failures} failed connections, {listed} domains added")
      .replace("{failures}", String(state.failures))
      .replace("{listed}", String(state.listed));
  });
</script>

{#if text !== ""}
  <span class="status" class:off={state !== null && !state.running} data-testid="autolist-status"
    >{text}</span
  >
{/if}

<style>
  .status {
    font-size: 0.9rem;
    color: var(--text-2);
  }
  .status.off {
    color: var(--yellow-bright);
  }
</style>
