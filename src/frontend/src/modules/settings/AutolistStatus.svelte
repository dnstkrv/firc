<script lang="ts">
  import { onDestroy } from "svelte";

  import { t } from "../../data/locale.svelte";
  import { settings } from "./settings.svelte";

  import { toast } from "../../utils/events";
  import { fetcher } from "../../utils/fetcher";

  type AutolistRes = {
    enabled: boolean;
    running: boolean;
    whyOff?: string;
    failures: number;
    listed: number;
    checking?: boolean;
    checkedAt?: number;
    switchedOff?: number;
  };

  let state = $state<AutolistRes | null>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stopped = false;

  async function load() {
    try {
      state = await fetcher.get<AutolistRes>("/system/autolist", { quiet: true });
    } catch {
      state = null;
    }
  }

  function schedule() {
    clearTimeout(timer);
    if (stopped) return;
    timer = setTimeout(
      async () => {
        await load();
        schedule();
      },
      state?.checking ? 2000 : 15000,
    );
  }

  $effect(() => {
    void settings.saved["app.autolist.enabled"];
    void settings.saved["app.autolist.group"];
    void settings.saved["app.autolist.recheck"];
    void load().then(schedule);
  });
  onDestroy(() => {
    stopped = true;
    clearTimeout(timer);
  });

  async function checkNow() {
    try {
      state = await fetcher.post<AutolistRes>("/system/autolist/check", undefined, { quiet: true });
      schedule();
    } catch (error) {
      toast.error(
        `${t("Request failed")}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  const text = $derived.by(() => {
    if (state === null || !state.enabled) return "";
    if (!state.running) return `${t("Not running")}: ${state.whyOff ?? ""}`;
    return t("Running: {failures} failed connections, {listed} domains added")
      .replace("{failures}", String(state.failures))
      .replace("{listed}", String(state.listed));
  });

  const checkText = $derived.by(() => {
    if (state === null || !state.running || settings.saved["app.autolist.recheck"] !== true)
      return "";
    if (state.checking) return t("checking…");
    if (!state.checkedAt) return t("not checked yet");
    const at = new Date(state.checkedAt * 1000).toLocaleString();
    return t("checked {at}, {n} switched off")
      .replace("{at}", at)
      .replace("{n}", String(state.switchedOff ?? 0));
  });
</script>

{#if text !== ""}
  <span class="status" class:off={state !== null && !state.running} data-testid="autolist-status">
    {text}
    {#if checkText !== ""}
      <span class="check">· {checkText}</span>
      <button type="button" class="now" disabled={state?.checking} onclick={checkNow}>
        {t("Check now")}
      </button>
    {/if}
  </span>
{/if}

<style>
  .status {
    display: inline-flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    font-size: 0.9rem;
    color: var(--text-2);
  }
  .status.off {
    color: var(--yellow-bright);
  }
  .now {
    padding: 2px 10px;
    border-radius: 8px;
    border: 1px solid var(--accent);
    background: transparent;
    color: var(--accent);
    font: inherit;
    font-size: 0.8rem;
    cursor: pointer;
  }
  .now:disabled {
    opacity: 0.5;
    cursor: default;
  }
</style>
