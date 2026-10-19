<script lang="ts">
  import Select from "../../../components/ui/Select.svelte";
  import { interfaces } from "../../../data/interfaces.svelte";
  import { locale, t } from "../../../data/locale.svelte";

  import type { Tunnel } from "../../../types";
  import { parseUplink, UPLINK_MORE, uplinkOptions, uplinkValue } from "../tunnel-editor";
  import type { ClientTunnel } from "../tunnels-data";

  let { tunnel = $bindable(), tunnels }: { tunnel: ClientTunnel; tunnels: Tunnel[] } = $props();

  let opened = $state<boolean | null>(null);
  const options = $derived(
    uplinkOptions(tunnel, tunnels, interfaces.list, t, {
      opened,
      locale: locale.current,
      onToggle: () => (opened = !options.find((o) => o.value === UPLINK_MORE)?.expanded),
    }),
  );
</script>

<Select
  ariaLabel={t("Way out to the internet")}
  {options}
  bind:selected={
    () => uplinkValue(tunnel.uplink),
    (v: string) => {
      if (v && v !== UPLINK_MORE) tunnel.uplink = parseUplink(v);
    }
  }
/>
