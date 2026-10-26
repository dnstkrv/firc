<script lang="ts">
  import { DropdownMenu } from "bits-ui";
  import { getContext } from "svelte";

  import { hosts } from "../../../data/hosts.svelte";
  import { interfaces } from "../../../data/interfaces.svelte";
  import { locale, t } from "../../../data/locale.svelte";
  import { policies } from "../../../data/policies.svelte";
  import { ask } from "../../../utils/confirm.svelte";
  import BulkDevicesDialog from "../dialogs/BulkDevicesDialog.svelte";
  import { GROUPS_STORE_CONTEXT, groupTitle, type GroupsStore } from "../groups.svelte";

  import {
    Check,
    Delete,
    Devices,
    Network,
    SelectOpen,
    ToggleLeft,
    ToggleRight,
    X,
  } from "../../../components/ui/icons";
  import { groupChoices, ifaceTitle, moreText, type IfaceItem } from "../../../data/iface-choices";
  import { replaceWith } from "../../../utils/device-bulk";
  import { coverageLabel } from "../../../utils/device-picker";
  import { counted } from "../../../utils/plural";
  import { selectionCountText } from "../selection";

  type Props = {
    /* The bar's own height, for the page to keep its last card clear of it. */
    height?: number;
  };

  let { height = $bindable(0) }: Props = $props();

  let bar = $state<HTMLDivElement>();
  let restOpen = $state(false);
  const choices = $derived(groupChoices(interfaces.list, []));

  const store = getContext<GroupsStore>(GROUPS_STORE_CONTEXT);
  if (!store) {
    throw new Error("GroupsStore context is missing");
  }

  let devicesOpen = $state(false);
  let devicesView = $state<"edit" | "replace">("edit");

  function editDevices(view: "edit" | "replace") {
    devicesView = view;
    devicesOpen = true;
  }

  const every = { allow: [], deny: [] };
  let selectedGroups = $derived.by(() => {
    const ids = new Set(store.selection);
    return store.data.filter((g) => ids.has(g.id));
  });
  let resetting = $derived(selectedGroups.filter((g) => replaceWith(g.devices, every) !== null));

  async function resetDevices() {
    const groups = selectedGroups;
    const changing = resetting;
    if (changing.length === 0) return;
    const items = groups.map((g) =>
      changing.includes(g)
        ? t("{group}: {now} → every device")
            .replace("{group}", () => groupTitle(g))
            .replace("{now}", () =>
              coverageLabel(g.devices, hosts.list, policies.list, t, locale.current),
            )
        : t("{group}: already every device, unchanged").replace("{group}", () => groupTitle(g)),
    );
    const ok = await ask({
      tone: "danger",
      title: counted(
        groups.length,
        locale.current,
        t("Reset the devices of {n} group?"),
        t("Reset the devices of {n} groups? (2-4)"),
        t("Reset the devices of {n} groups?"),
      ),
      message: t(
        "The groups will work for every device, new ones included. Traffic of the devices excluded now goes through the group as soon as the change applies. The change needs saving, like any other group edit.",
      ),
      items,
      confirm: counted(
        changing.length,
        locale.current,
        t("Reset in {n} group"),
        t("Reset in {n} groups (2-4)"),
        t("Reset in {n} groups"),
      ),
    });
    if (ok) store.setSelectedDevices((g) => replaceWith(g.devices, every));
  }

  let countText = $derived(selectionCountText(store.selection.length, locale.current, t));

  function handleKeydown(event: KeyboardEvent) {
    if (event.key !== "Escape" || event.defaultPrevented) return;
    /* Not while the Groups tab is hidden: the bar is not on screen. */
    if (!bar?.getClientRects().length) return;
    if (
      document.querySelector(
        "[data-dropdown-menu-content], [data-select-content], [data-popover-content], [data-dialog-content]",
      )
    ) {
      return;
    }
    const active = document.activeElement;
    if (
      active instanceof HTMLTextAreaElement ||
      (active instanceof HTMLElement && active.isContentEditable) ||
      (active instanceof HTMLInputElement &&
        !["checkbox", "radio", "button", "submit", "reset"].includes(active.type))
    ) {
      return;
    }
    store.clearSelection();
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<div
  bind:this={bar}
  class="bulk-bar"
  role="region"
  aria-label={t("Selected groups")}
  bind:offsetHeight={height}
>
  <div class="bulk-row bulk-selection">
    <strong class="bulk-count" role="status">{countText}</strong>
    <button type="button" class="bulk-button" onclick={() => store.selectAll()}>
      <Check size={18} />{t("Select all")}
    </button>
    <button type="button" class="bulk-button" onclick={() => store.clearSelection()}>
      <X size={18} />{t("Clear selection")}
    </button>
  </div>

  <div class="bulk-row bulk-actions">
    <DropdownMenu.Root
      onOpenChange={(open) => {
        if (open) restOpen = false;
      }}
    >
      <DropdownMenu.Trigger class="bulk-button">
        <Network size={18} /><span class="bulk-label">{t("Interface")}</span><SelectOpen
          size={16}
        />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          class="bulk-menu"
          side="top"
          align="start"
          sideOffset={8}
          collisionPadding={8}
        >
          {#each choices.head as item (item.id)}
            {@render ifaceItem(item)}
          {/each}
          {#if choices.blackhole}
            <DropdownMenu.Separator class="bulk-menu-separator" />
            <DropdownMenu.Item
              class="bulk-menu-item"
              onSelect={() => store.setSelectedInterface("blackhole")}
            >
              <span class="bulk-menu-label bulk-menu-danger">{t("Block")}</span>
            </DropdownMenu.Item>
          {/if}
          {#if choices.block}
            {#if !choices.blackhole}<DropdownMenu.Separator class="bulk-menu-separator" />{/if}
            <DropdownMenu.Item
              class="bulk-menu-item"
              onSelect={() => store.setSelectedInterface("block")}
            >
              <span class="bulk-menu-label bulk-menu-warn">{t("Block by DNS")}</span>
            </DropdownMenu.Item>
          {/if}
          {#if choices.rest.length > 0}
            <DropdownMenu.Separator class="bulk-menu-separator" />
            <DropdownMenu.Item
              class="bulk-menu-item"
              aria-expanded={restOpen}
              onSelect={(e) => {
                e.preventDefault();
                restOpen = !restOpen;
              }}
            >
              <span class="bulk-menu-label">{moreText(choices.rest.length, locale.current, t)}</span
              >
              <span class="bulk-menu-chevron" class:open={restOpen}><SelectOpen size={16} /></span>
            </DropdownMenu.Item>
            {#if restOpen}
              {#each choices.rest as item (item.id)}
                {@render ifaceItem(item)}
              {/each}
            {/if}
          {/if}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>

    <DropdownMenu.Root>
      <DropdownMenu.Trigger class="bulk-button bulk-devices" aria-label={t("Devices")}>
        <Devices size={18} /><span class="bulk-label label-devices">{t("Devices")}</span><span
          class="devices-chevron"><SelectOpen size={16} /></span
        >
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          class="bulk-menu"
          side="top"
          align="start"
          sideOffset={8}
          collisionPadding={8}
        >
          <DropdownMenu.Item class="bulk-menu-item" onSelect={() => editDevices("edit")}>
            <span class="bulk-menu-text">
              <span class="bulk-menu-label">{t("Edit…")}</span>
              <span class="bulk-menu-desc"
                >{t(
                  "Add or remove devices and policies; everything else stays as each group has it",
                )}</span
              >
            </span>
          </DropdownMenu.Item>
          <DropdownMenu.Item class="bulk-menu-item" onSelect={() => editDevices("replace")}>
            <span class="bulk-menu-text">
              <span class="bulk-menu-label">{t("Replace…")}</span>
              <span class="bulk-menu-desc"
                >{t("Give every selected group the same device choice")}</span
              >
            </span>
          </DropdownMenu.Item>
          <DropdownMenu.Separator class="bulk-menu-separator" />
          <DropdownMenu.Item
            class="bulk-menu-item"
            disabled={resetting.length === 0}
            onSelect={() => void resetDevices()}
          >
            <span class="bulk-menu-text">
              <span class="bulk-menu-label bulk-menu-danger">{t("Reset: every device")}</span>
              <span class="bulk-menu-desc">{t("Remove every device restriction")}</span>
            </span>
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>

    <DropdownMenu.Root>
      <DropdownMenu.Trigger class="bulk-button">
        <ToggleLeft size={18} />
        <span class="bulk-label label-long">{t("Enable / disable")}</span>
        <span class="bulk-label label-short">{t("On/off")}</span>
        <SelectOpen size={16} />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          class="bulk-menu"
          side="top"
          align="start"
          sideOffset={8}
          collisionPadding={8}
        >
          <DropdownMenu.Item class="bulk-menu-item" onSelect={() => store.setSelectedEnable(true)}>
            <ToggleRight size={18} />
            <span class="bulk-menu-label">{t("Enable selected")}</span>
          </DropdownMenu.Item>
          <DropdownMenu.Item class="bulk-menu-item" onSelect={() => store.setSelectedEnable(false)}>
            <ToggleLeft size={18} />
            <span class="bulk-menu-label">{t("Disable selected")}</span>
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>

    <button type="button" class="bulk-button" onclick={() => store.deleteSelected()}>
      <Delete size={18} /><span class="bulk-label">{t("Delete")}</span>
    </button>
  </div>
</div>

<BulkDevicesDialog bind:open={devicesOpen} bind:view={devicesView} />

{#snippet ifaceItem(item: IfaceItem)}
  {@const label = ifaceTitle(item)}
  <DropdownMenu.Item class="bulk-menu-item" onSelect={() => store.setSelectedInterface(item.id)}>
    <span class="bulk-menu-label">{label.title}</span>
    {#if label.sub}<span class="bulk-menu-sub">{label.sub}</span>{/if}
    {#if item.role === "wan"}<span class="bulk-menu-tag">{t("provider")}</span>{/if}
  </DropdownMenu.Item>
{/snippet}

<style>
  .bulk-bar {
    position: fixed;
    left: 50%;
    bottom: calc(1.25rem + env(safe-area-inset-bottom));
    transform: translateX(-50%);
    z-index: 6;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem 1rem;
    width: max-content;
    max-width: min(calc(100vw - 2rem), 1000px);
    box-sizing: border-box;
    padding: 0.55rem 0.6rem;
    border: 1px solid color-mix(in oklab, var(--accent) 55%, transparent);
    border-radius: 14px;
    background: color-mix(in oklab, var(--accent) 7%, var(--bg-dark-extra));
    box-shadow:
      0 12px 40px #0006,
      0 0 0 4px color-mix(in oklab, var(--accent) 10%, transparent);
    color: var(--text);
  }

  .bulk-row {
    display: flex;
    flex: 1 1 auto;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem;
    min-width: 0;
  }

  .bulk-row > :global(*) {
    flex: 1 1 auto;
  }

  .bulk-row > .bulk-count {
    flex: 1 0 auto;
    padding: 0 0.6rem 0 0.5rem;
    font-weight: 600;
    white-space: nowrap;
  }

  .bulk-bar :global(.bulk-button) {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.45rem;
    height: 2.6rem;
    padding: 0 0.75rem;
    box-sizing: border-box;
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    background: var(--bg-light);
    color: var(--text-2);
    font: 400 1rem var(--font);
    white-space: nowrap;
    cursor: pointer;
    transition:
      background-color 0.1s ease-in-out,
      color 0.1s ease-in-out;
  }

  .bulk-bar :global(.bulk-button:hover),
  .bulk-bar :global(.bulk-button[data-state="open"]) {
    border-color: var(--bg-light-extra);
    background: var(--bg-light-extra);
    color: var(--text);
  }

  .bulk-bar :global(.bulk-button:focus-visible) {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .bulk-bar :global(.bulk-button svg) {
    flex: none;
  }

  .bulk-label {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .label-short {
    display: none;
  }

  .devices-chevron {
    display: inline-flex;
  }

  :global(.bulk-menu[data-dropdown-menu-content]) {
    z-index: 11;
    min-width: 13rem;
    max-width: calc(100vw - 1rem);
    box-sizing: border-box;
    padding: 0.35rem;
    border-radius: 0.6rem;
  }

  :global(.bulk-menu-item[data-dropdown-menu-item]) {
    display: flex;
    align-items: center;
    justify-content: flex-start;
    gap: 0.5rem;
    padding: 0.55rem 0.6rem;
    border-radius: 0.4rem;
    color: var(--text-2);
    cursor: pointer;
    outline: none;
  }

  :global(.bulk-menu-item[data-dropdown-menu-item][data-highlighted]) {
    background: var(--bg-light-extra);
    color: var(--text);
  }

  :global(.bulk-menu-label) {
    white-space: nowrap;
  }

  .bulk-menu-text {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    max-width: 20rem;
  }

  .bulk-menu-desc {
    font-size: 0.75rem;
    color: var(--text-2);
    white-space: normal;
  }

  :global(.bulk-menu-item[data-dropdown-menu-item][data-disabled]) {
    opacity: 0.5;
    cursor: not-allowed;
  }

  :global(.bulk-menu-sub) {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-2);
    white-space: nowrap;
  }

  :global(.bulk-menu-tag) {
    font-size: 0.7rem;
    color: var(--text-2);
    opacity: 0.8;
  }

  :global(.bulk-menu-danger) {
    color: var(--danger);
  }
  :global(.bulk-menu-warn) {
    color: var(--orange);
  }

  :global(.bulk-menu-separator) {
    height: 1px;
    margin: 0.25rem 0.2rem;
    background: var(--bg-light-extra);
  }

  .bulk-menu-chevron {
    display: flex;
    margin-left: auto;
    transition: transform 0.16s ease;
  }

  .bulk-menu-chevron.open {
    transform: rotate(180deg);
  }

  @media (max-width: 600px) {
    .bulk-bar {
      left: 0.5rem;
      right: 0.5rem;
      bottom: calc(0.5rem + env(safe-area-inset-bottom));
      transform: none;
      width: auto;
      max-width: none;
      padding: 0.5rem;
    }

    .bulk-actions {
      gap: 0.4rem;
    }

    .bulk-bar :global(.bulk-button) {
      min-width: 0;
      gap: 0.25rem;
      padding: 0 0.3rem;
      font-size: 0.875rem;
    }

    .bulk-bar :global(.bulk-button svg) {
      width: 16px;
      height: 16px;
    }

    .label-long {
      display: none;
    }

    .label-short {
      display: inline;
    }

    .label-devices,
    .devices-chevron {
      display: none;
    }

    .bulk-actions > :global(.bulk-devices) {
      flex: 0 0 auto;
    }
  }
</style>
