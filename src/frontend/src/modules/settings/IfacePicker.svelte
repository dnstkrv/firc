<script lang="ts">
  import { onMount } from "svelte";

  import Select from "../../components/ui/Select.svelte";
  import { fetchInterfaces, interfaces } from "../../data/interfaces.svelte";
  import { t } from "../../data/locale.svelte";

  import { ifaceTitle, isSink } from "../../data/iface-choices";

  type Props = {
    value: string;
    onchange: (id: string) => void;
    ariaLabel: string;
    invalid?: boolean;
    changed?: string;
  };
  let { value, onchange, ariaLabel, invalid = false, changed = "" }: Props = $props();

  const DEFAULT = "-";

  onMount(() => {
    if (interfaces.list.length === 0) void fetchInterfaces();
  });

  const offered = $derived([
    ...interfaces.list.filter((i) => i.role === "wan"),
    ...interfaces.list.filter((i) => i.role !== "wan" && i.role !== "lan" && !isSink(i.id)),
  ]);
  const options = $derived([
    { value: DEFAULT, label: t("Default route") },
    ...offered.map((i) => {
      const { title, sub } = ifaceTitle(i);
      return { value: i.id, label: title, description: sub, mono: true };
    }),
    ...(value !== "" && !offered.some((i) => i.id === value)
      ? [{ value, label: value, missing: true }]
      : []),
  ]);
</script>

<div class="iface-picker" class:invalid>
  <Select
    {options}
    selected={value === "" ? DEFAULT : value}
    onValueChange={(v: string) => onchange(v === DEFAULT ? "" : v)}
    {ariaLabel}
    showSelectedDescription={false}
    class="iface-picker-select {changed}"
  />
</div>

<style>
  .iface-picker {
    width: 100%;
    min-width: 0;
  }
  .iface-picker :global(.iface-picker-select),
  .iface-picker :global(.iface-picker-select [data-select-root]) {
    width: 100%;
    max-width: 100%;
  }
  .iface-picker :global(.iface-picker-select [data-select-trigger]) {
    width: 100%;
    height: 2.25rem;
    padding: 0 10px;
    border-radius: 8px;
    background: var(--bg-light);
    border: 1px solid var(--bg-light);
    box-sizing: border-box;
  }
  .iface-picker :global(.iface-picker-select [data-select-trigger] > .selected) {
    width: 100%;
    justify-content: space-between;
  }
  .iface-picker :global(.iface-picker-select .selected-value) {
    padding-left: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .iface-picker :global(.iface-picker-select.changed-live [data-select-trigger]) {
    background: var(--bg-dark);
    border-color: var(--accent);
  }
  .iface-picker.invalid :global(.iface-picker-select [data-select-trigger]) {
    border-color: var(--danger);
  }
</style>
