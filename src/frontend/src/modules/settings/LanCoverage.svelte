<script lang="ts">
  import { array, boolean, fallback, object, safeParse, string } from "valibot";

  import { fetchHosts, hosts } from "../../data/hosts.svelte";
  import { interfaces } from "../../data/interfaces.svelte";
  import { t } from "../../data/locale.svelte";
  import { fetchPolicies, policies } from "../../data/policies.svelte";

  import { ifaceTitle } from "../../data/iface-choices";
  import { DeviceSelectorSchema } from "../../types";
  import { fetcher } from "../../utils/fetcher";
  import { uncoveredSegments } from "../../utils/lan-coverage";

  type Props = { values: string[]; onchange: (values: string[]) => void };
  let { values, onchange }: Props = $props();

  const CoveringGroups = array(
    object({
      name: fallback(string(), ""),
      enable: fallback(boolean(), true),
      devices: fallback(DeviceSelectorSchema, { allow: [], deny: [] }),
    }),
  );

  let groups = $state<
    { name: string; enable: boolean; devices: { allow: string[]; deny: string[] } }[]
  >([]);

  $effect(() => {
    void fetchHosts();
    void fetchPolicies(true);
    fetcher
      .get<{ groups?: unknown }>("/groups", { quiet: true })
      .then((data) => {
        const parsed = safeParse(CoveringGroups, data?.groups ?? []);
        groups = parsed.success ? parsed.output : [];
      })
      .catch(() => (groups = []));
  });

  const uncovered = $derived(uncoveredSegments(groups, hosts.list, policies.list, values));
  const titleOf = (id: string) =>
    ifaceTitle(interfaces.list.find((i) => i.id === id) ?? { id }).title;
</script>

{#each uncovered as u (u.segment)}
  <div class="lan-coverage" role="status">
    <span>
      {t("Devices of groups {names} are in {segment}: their DNS is not intercepted")
        .replace("{names}", () => u.groups.join(", "))
        .replace("{segment}", () => titleOf(u.segment))}
    </span>
    <button type="button" onclick={() => onchange([...values, u.segment])}>
      {t("Add {segment}").replace("{segment}", () => titleOf(u.segment))}
    </button>
  </div>
{/each}

<style>
  .lan-coverage {
    grid-column: 1 / -1;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 12px;
    padding: 8px 10px;
    border-radius: 8px;
    background: color-mix(in oklab, var(--yellow) 10%, transparent);
    color: var(--yellow);
    font-size: 0.85rem;
    overflow-wrap: anywhere;
  }
  button {
    flex: none;
    padding: 4px 10px;
    border-radius: 8px;
    border: 1px solid var(--yellow);
    background: transparent;
    color: var(--yellow);
    font: inherit;
    cursor: pointer;
  }
</style>
