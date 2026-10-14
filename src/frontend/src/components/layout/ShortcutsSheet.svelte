<script lang="ts">
  import { Popover } from "bits-ui";

  import { t } from "../../data/locale.svelte";
  import Kbd from "../ui/Kbd.svelte";

  import { MOD } from "../../utils/keys";
  import { Keyboard } from "../ui/icons";

  let open = $state(false);

  let rows = $derived([
    { label: t("Save"), keys: [MOD, "S"] },
    { label: t("Search groups"), keys: [MOD, "F"] },
    { label: t("Apply rule import"), keys: [MOD, "Enter"] },
    { label: t("Backup interface (in the picker)"), keys: ["Shift", "Enter"] },
    { label: t("Close a dialog or menu"), keys: ["Esc"] },
  ]);

  function typing(target: EventTarget | null) {
    return (
      target instanceof HTMLElement &&
      (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName))
    );
  }

  function onKey(e: KeyboardEvent) {
    if (e.key !== "?" || e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented) return;
    if (typing(e.target)) return;
    if (document.querySelector("[data-dialog-content], [data-alert-dialog-content]")) return;
    e.preventDefault();
    open = !open;
  }
</script>

<svelte:window onkeydown={onKey} />

<Popover.Root bind:open>
  <Popover.Trigger class="keys-button" aria-label={t("Keyboard shortcuts")}>
    <Keyboard size={18} />
  </Popover.Trigger>
  <Popover.Portal>
    <Popover.Content class="shortcuts-sheet" align="center" sideOffset={6} collisionPadding={8}>
      <div class="shortcuts-title">{t("Keyboard shortcuts")}</div>
      {#each rows as row}
        <div class="shortcut-row">
          <span>{row.label}</span>
          <Kbd keys={row.keys} />
        </div>
      {/each}
      <div class="shortcuts-note">
        {t("On a Mac, ⌘ instead of Ctrl. Open this list:")}
        <Kbd keys={["?"]} />
      </div>
    </Popover.Content>
  </Popover.Portal>
</Popover.Root>

<style>
  :global(.keys-button) {
    box-sizing: border-box;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 35px;
    padding: 0.4rem 0.55rem;
    color: var(--text-2);
    background: var(--bg-light);
    border: 1px solid transparent;
    border-radius: 0.5rem;
    cursor: pointer;
  }

  :global(.keys-button:hover) {
    background-color: var(--bg-dark);
    color: var(--text);
    border-color: var(--bg-light-extra);
  }

  :global(.shortcuts-sheet) {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 22rem;
    max-width: calc(100vw - 1rem);
    box-sizing: border-box;
    padding: 0.7rem 0.8rem 0.6rem;
    background-color: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-popover);
    color: var(--text);
    font-size: 0.9rem;
    z-index: 30;
    outline: none;
  }

  .shortcuts-title {
    font-weight: 600;
    margin-bottom: 0.35rem;
  }

  .shortcut-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1.5rem;
    padding: 0.3rem 0.1rem;
  }

  .shortcuts-note {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    margin-top: 0.3rem;
    color: var(--text-2);
    font-size: 0.75rem;
  }
</style>
