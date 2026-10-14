<script lang="ts">
  import Kbd from "../../../components/ui/Kbd.svelte";
  import Select from "../../../components/ui/Select.svelte";
  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { groupInterfaces } from "../../../data/interfaces.svelte";
  import { t } from "../../../data/locale.svelte";

  import {
    backupNote,
    backupText,
    canBackup,
    chainLabel,
    entryNumber,
    ifaceList,
    ifaceValue,
    toggleEntry,
  } from "../iface-list";
  import { clockMinutes, type GroupLive } from "../live-state";

  type Props = {
    value: string | string[];
    live?: GroupLive;
    unsaved?: boolean;
    closed: "active" | "chain";
    class?: string;
  };

  let { value = $bindable(), live, unsaved = false, closed, class: className }: Props = $props();

  let list = $derived(ifaceList({ interface: value }));
  let options = $derived(
    groupInterfaces().map((item) => ({
      value: item.id,
      label: item.id,
      description: item.name,
      ariaDescription: canBackup(list, item.id)
        ? t("Shift+Enter — add as a backup or remove")
        : undefined,
    })),
  );
  let anyCircle = $derived(options.some((o) => canBackup(list, o.value)));
  let chain = $derived(closed === "chain" && list.length > 1);
  let note = $derived(closed === "active" && !unsaved ? backupNote(list, live) : null);
  let shown = $derived(closed === "active" && !unsaved ? (live?.active ?? list[0]) : list[0]);

  function toggle(id: string) {
    value = ifaceValue(toggleEntry(list, id));
  }

  function collapse(id: string) {
    if (list.length > 1 && entryNumber(list, id) === 1) value = id;
  }

  function stateOf(id: string) {
    return live?.interfaces?.find((s) => s.name === id)?.state ?? "unknown";
  }

  function onKey(e: KeyboardEvent) {
    if (e.key !== "Enter" || !e.shiftKey) return;
    const trigger = (e.currentTarget as HTMLElement).querySelector("[data-select-trigger]");
    const highlighted = trigger?.getAttribute("aria-activedescendant");
    const id = highlighted ? document.getElementById(highlighted)?.dataset.value : undefined;
    if (!id) return;
    e.preventDefault();
    e.stopPropagation();
    toggle(id);
  }
</script>

{#snippet lead(option: { value: string })}
  {@const n = entryNumber(list, option.value)}
  {#if canBackup(list, option.value)}
    <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
    <span
      class="iface-circle"
      class:free={n === null}
      class:first={n === 1}
      data-circle={option.value}
      aria-hidden="true"
      onpointerdown={(e) => e.preventDefault()}
      onpointerup={(e) => {
        e.preventDefault();
        e.stopPropagation();
      }}
      onclick={(e) => {
        e.stopPropagation();
        toggle(option.value);
      }}>{n ?? ""}</span
    >
  {:else if anyCircle}
    <span class="iface-gap"></span>
  {/if}
  <span class="iface-dot" data-state={stateOf(option.value)}></span>
{/snippet}

{#snippet closedValue()}
  {#if chain}
    <span title={chainLabel(list)}
      >{list[0]} <span class="iface-chain">→ {chainLabel(list.slice(1))}</span></span
    >
  {:else}
    {shown}
    {#if note}
      {@const text = backupText(note, t, clockMinutes)}
      <span class="iface-note">
        <Tooltip value={text}>
          <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
          <span class="iface-amber" role="img" tabindex="0" aria-label={text}></span>
        </Tooltip>
      </span>
    {/if}
  {/if}
{/snippet}

{#snippet footer()}
  <div class="iface-foot">
    <div class="iface-footer">{t("1 — first, 2–4 — backups in order")}</div>
    <div class="iface-keys">
      <Kbd keys={["Shift", "Enter"]} />
      {t("— add or remove a backup")}
    </div>
  </div>
{/snippet}

<Select
  {options}
  bind:selected={
    () => list[0],
    (v: string) => {
      if (v) value = v;
    }
  }
  {shown}
  onItemPointerUp={collapse}
  showSelectedDescription={!chain}
  {lead}
  closed={chain || note ? closedValue : undefined}
  footer={anyCircle ? footer : undefined}
  class={className}
  onkeydowncapture={onKey}
/>

<style>
  .iface-circle {
    width: 20px;
    height: 20px;
    margin-right: 0.3rem;
    box-sizing: border-box;
    border-radius: 50%;
    border: 1.5px dashed transparent;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    background: #4a4d63;
    color: var(--text);
    padding-top: 1px;
    font-size: 11px;
    line-height: 1;
    cursor: pointer;
  }
  .iface-circle.first {
    background: var(--accent);
    color: var(--bg-dark-extra);
    font-weight: 600;
  }
  .iface-circle.free {
    background: transparent;
  }
  :global([data-select-item]:hover) .iface-circle.free,
  :global([data-select-item][data-highlighted]) .iface-circle.free {
    border-color: #555;
  }

  .iface-gap {
    width: 20px;
    margin-right: 0.3rem;
    flex: none;
  }

  .iface-dot {
    width: 7px;
    height: 7px;
    margin-right: 0.3rem;
    border-radius: 50%;
    flex: none;
    background: #666;
  }
  .iface-dot[data-state="alive"] {
    background: var(--green);
  }
  .iface-dot[data-state="dead"] {
    background: var(--red);
  }

  .iface-foot {
    margin-top: 0.1rem;
    padding: 0.35rem 0.35rem 0.1rem;
    border-top: 1px solid var(--bg-light-extra);
    color: var(--text-2);
    font-size: 11px;
    line-height: 1.35;
    white-space: normal;
  }

  .iface-keys {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    margin-top: 0.3rem;
  }

  @media (hover: none) {
    .iface-keys {
      display: none;
    }
  }

  .iface-note {
    display: inline-flex;
    margin-left: 0.35rem;
    vertical-align: middle;
  }

  .iface-amber {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--orange);
  }

  .iface-chain {
    color: var(--text-2);
  }
</style>
