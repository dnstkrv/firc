<script lang="ts">
  import GenericDialog from "../../components/ui/GenericDialog.svelte";
  import { t } from "../../data/locale.svelte";

  import type { UpdateRes } from "./update";

  type Props = {
    open: boolean;
    res: UpdateRes;
  };

  let { open = $bindable(), res }: Props = $props();

  const result = $derived(res.result);
</script>

{#if result}
  <GenericDialog
    {open}
    title={t("Why {version} did not install").replace("{version}", () => result.version)}
    maxWidth={640}
    on:close={() => (open = false)}
  >
    <div slot="body" class="body">
      <p>
        {t("opkg exit {code}; firc {installed} is still running.")
          .replace("{code}", String(result.opkgExit))
          .replace("{installed}", () => res.installed.version)}
      </p>
      {#if result.log}
        <pre data-testid="update-log">{result.log}</pre>
      {:else}
        <p class="muted">{t("opkg printed nothing.")}</p>
      {/if}
      <p class="muted">
        {t("opkg's output also went to the router's system log, tagged firc-update.")}
      </p>
    </div>
  </GenericDialog>
{/if}

<style>
  .body {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    min-width: 0;
  }

  p {
    margin: 0;
  }

  .muted {
    font-size: 0.85em;
    color: var(--text-2);
  }

  pre {
    margin: 0;
    max-height: 50vh;
    overflow: auto;
    padding: 0.6rem 0.75rem;
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    background: var(--bg-dark-extra);
    font: 0.8rem/1.45 var(--font-mono);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
</style>
