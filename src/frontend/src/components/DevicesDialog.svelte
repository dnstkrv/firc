<script lang="ts">
  import { createEventDispatcher } from "svelte";

  import { fetchHosts } from "../data/hosts.svelte";
  import { t } from "../data/locale.svelte";
  import { fetchPolicies } from "../data/policies.svelte";
  import { loadSettings, settings } from "../modules/settings/settings.svelte";
  import DevicePicker from "./DevicePicker.svelte";
  import Button from "./ui/Button.svelte";
  import GenericDialog from "./ui/GenericDialog.svelte";

  import type { DeviceSelector } from "../types";
  import { joinSelector, splitSelector } from "../utils/device-picker";
  import { Info } from "./ui/icons";

  type DevicesTarget = { id: string; devices: DeviceSelector };

  let {
    open = $bindable(false),
    target = null,
  }: { open?: boolean; target?: DevicesTarget | null } = $props();

  const dispatch = createEventDispatcher();

  let selector = $state.raw<DeviceSelector>({ allow: [], deny: [] });
  let nothingChosen = $state(false);
  let invalid = $state(false);
  let manualOpen = $state(false);

  $effect(() => {
    if (open) {
      void fetchPolicies();
      void fetchHosts();
      if (!settings.loaded) void loadSettings();
    }
  });

  let helpOpen = $state(false);
  let clampText = $derived.by(() => {
    const secs = Number(settings.saved["app.addressPool.ttlClamp"] ?? 300);
    return secs % 60 === 0
      ? t("{n} min").replace("{n}", String(secs / 60))
      : t("{n} s").replace("{n}", String(secs));
  });

  function close() {
    open = false;
    dispatch("close");
  }

  function submit() {
    if (invalid) {
      manualOpen = true;
      return;
    }
    if (nothingChosen || !target) return;
    /* nothing touched: the draft stays as it was, and the group clean */
    if (JSON.stringify(selector) !== JSON.stringify(joinSelector(splitSelector(target.devices))))
      target.devices = selector;
    close();
  }
</script>

<GenericDialog {open} title={t("Devices")} maxWidth={640} on:close={close} on:submit={submit}>
  <button
    slot="title"
    type="button"
    class="help-toggle"
    aria-label={t("How the device choice works")}
    aria-expanded={helpOpen}
    aria-controls="devices-help"
    onclick={() => (helpOpen = !helpOpen)}><Info size={18} /></button
  >
  <div slot="body" class="dialog-body">
    {#if helpOpen}
      <section id="devices-help" class="block help">
        <div class="label">{t("How the device choice works")}</div>
        <p>
          {t(
            "For a denied device the group is as if switched off. Its DNS queries get the ordinary answer, and its traffic goes straight out through the main internet, past the group's interface. This is not a block: a site the provider blocks will not open directly.",
          )}
        </p>
        <p>
          <strong>{t("A change does not take effect at once.")}</strong>
          {t(
            "A device that has already asked for a domain of the group keeps the address firc gave it in its DNS cache for up to {clamp}. Until that cache expires, the site will not open on a denied device: firc does not let its addresses past the group. Flushing the device's DNS cache or restarting the browser speeds it up.",
          ).replace("{clamp}", () => clampText)}
        </p>
        <p>
          {t(
            "The other way round too: a device just allowed goes direct until the TTL of the answer it got earlier expires.",
          )}
        </p>
      </section>
    {/if}
    <DevicePicker
      seed={target?.devices}
      seedKey={open && target ? target.id : null}
      bind:selector
      bind:nothingChosen
      bind:invalid
      bind:manualOpen
    />
  </div>

  <div slot="actions" class="devices-actions">
    {#if nothingChosen}
      <p class="hint done-hint" id="devices-done-hint">
        {t(
          "Switch on at least one device or policy, or choose “For every device”. To make the group work for nobody, switch the group off on the main page.",
        )}
      </p>
    {/if}
    <Button type="button" onclick={close}>{t("Cancel")}</Button>
    <!-- type="submit" only: an onclick as well ran submit() twice -->
    <Button
      type="submit"
      disabled={nothingChosen}
      aria-describedby={nothingChosen ? "devices-done-hint" : undefined}
      class="primary"
    >
      {t("Done")}
    </Button>
  </div>
</GenericDialog>

<style>
  .dialog-body {
    display: flex;
    flex-direction: column;
    gap: 1.1rem;
    min-width: 0;
  }

  .block {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    min-width: 0;
  }

  .label {
    font-size: 0.95em;
    font-weight: 600;
    color: var(--text);
  }

  .help-toggle {
    display: inline-flex;
    vertical-align: middle;
    margin-left: 0.4rem;
    padding: 0.1rem;
    border: none;
    background: none;
    color: var(--text-2);
    cursor: pointer;
  }

  .help-toggle:hover,
  .help-toggle[aria-expanded="true"] {
    color: var(--accent);
  }

  .help p {
    font-size: 0.85em;
    color: var(--text-2);
    margin: 0;
  }

  .help strong {
    color: var(--text);
  }

  .hint {
    font-size: 0.8em;
    color: var(--text-2);
    margin: 0;
  }

  .devices-actions {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 0.75rem;
  }

  .done-hint {
    flex: 1 1 auto;
    min-width: 0;
    color: var(--orange);
  }
</style>
