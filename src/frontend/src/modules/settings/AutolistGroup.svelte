<script lang="ts">
  import { onMount } from "svelte";

  import Select from "../../components/ui/Select.svelte";
  import { fetchInterfaces, interfaces } from "../../data/interfaces.svelte";
  import { t } from "../../data/locale.svelte";

  import { ifaceTitle, isSink } from "../../data/iface-choices";
  import { toast } from "../../utils/events";
  import { fetcher } from "../../utils/fetcher";

  type Props = {
    value: string;
    onchange: (id: string) => void;
    ariaLabel: string;
    invalid?: boolean;
    changed?: string;
  };
  let { value, onchange, ariaLabel, invalid = false, changed = "" }: Props = $props();

  type GroupItem = { id: string; name: string; list?: unknown };

  const NEW = "new";
  const AUTOLIST_NAME = $derived(t("Autolist"));

  let groups = $state<GroupItem[]>([]);
  let loaded = $state(false);
  let creating = $state(false);
  let wantNew = $state(false);
  let iface = $state("");

  async function loadGroups() {
    try {
      const res = await fetcher.get<{ groups?: GroupItem[] }>("/groups", { quiet: true });
      groups = res?.groups ?? [];
    } catch (error) {
      console.error("Failed to load groups:", error);
    } finally {
      loaded = true;
    }
  }

  onMount(() => {
    void loadGroups();
    if (interfaces.list.length === 0) void fetchInterfaces();
  });

  const manual = $derived(groups.filter((g) => g.list === undefined || g.list === null));
  const known = $derived(value === "" || groups.some((g) => g.id === value));
  const tunnels = $derived([
    ...interfaces.list.filter((i) => i.role === "tunnel"),
    ...interfaces.list.filter((i) => i.role !== "tunnel" && i.role !== "lan" && !isSink(i.id)),
  ]);

  const options = $derived([
    { value: NEW, label: t("New group {name}").replace("{name}", AUTOLIST_NAME) },
    ...manual.map((g) => ({ value: g.id, label: g.name || g.id, description: g.id, mono: true })),
    ...(known ? [] : [{ value, label: t("A group that no longer exists"), missing: true }]),
  ]);
  const ifaceOptions = $derived(
    tunnels.map((i) => {
      const { title, sub } = ifaceTitle(i);
      return { value: i.id, label: title, description: sub, mono: true };
    }),
  );

  function pick(v: string) {
    if (v === NEW) {
      wantNew = true;
      return;
    }
    wantNew = false;
    onchange(v);
  }

  async function create() {
    if (iface === "" || creating) return;
    creating = true;
    try {
      const made = await fetcher.post<GroupItem>(
        "/groups?save=true",
        { name: AUTOLIST_NAME, interface: iface, enable: true, rules: [] },
        { quiet: true },
      );
      groups = [...groups, made];
      wantNew = false;
      onchange(made.id);
      toast.success(t("Group {name} created").replace("{name}", AUTOLIST_NAME));
    } catch (error) {
      toast.error(
        `${t("Request failed")}: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      creating = false;
    }
  }
</script>

<div class="autolist-group {changed}" class:invalid>
  <Select
    {options}
    selected={wantNew ? NEW : value}
    shown={wantNew ? NEW : value === "" ? undefined : value}
    onValueChange={pick}
    {ariaLabel}
    disabled={!loaded}
    class="group-select"
  />
  {#if !wantNew && value === "" && loaded}
    <span class="hint">{t("Not chosen: nothing is added")}</span>
  {/if}
  {#if wantNew}
    <div class="new">
      <Select
        options={ifaceOptions}
        selected={iface}
        onValueChange={(v: string) => (iface = v)}
        ariaLabel={t("Interface of the new group")}
        class="iface-select"
      />
      <button type="button" class="create" disabled={iface === "" || creating} onclick={create}>
        {t("Create")}
      </button>
    </div>
    <span class="hint">{t("Where the added domains will go")}</span>
  {/if}
</div>

<style>
  .autolist-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
    width: 100%;
    border: 1px solid transparent;
    border-radius: 8px;
  }
  .autolist-group.changed-live {
    border-color: var(--accent);
  }
  .autolist-group.invalid {
    border-color: var(--danger);
  }
  .new {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .hint {
    font-size: 0.8rem;
    color: var(--text-2);
  }
  .create {
    flex: none;
    padding: 6px 12px;
    border-radius: 8px;
    border: 1px solid var(--accent);
    background: transparent;
    color: var(--accent);
    font: inherit;
    cursor: pointer;
  }
  .create:disabled {
    opacity: 0.5;
    cursor: default;
  }
</style>
