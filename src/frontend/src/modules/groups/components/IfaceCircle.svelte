<script lang="ts">
  type Props = {
    id: string;
    n: number | null;
    ontoggle: (id: string) => void;
  };

  let { id, n, ontoggle }: Props = $props();
</script>

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<span
  class="iface-circle"
  class:free={n === null}
  class:first={n === 1}
  data-circle={id}
  aria-hidden="true"
  onpointerdown={(e) => e.preventDefault()}
  onpointerup={(e) => {
    e.preventDefault();
    e.stopPropagation();
  }}
  onclick={(e) => {
    e.stopPropagation();
    ontoggle(id);
  }}>{n ?? ""}</span
>

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
    border-style: solid;
    border-color: #6a6d85;
  }
  :global([data-select-item]:hover) .iface-circle.free,
  :global([data-select-item][data-highlighted]) .iface-circle.free,
  :global([data-dropdown-menu-item]:hover) .iface-circle.free,
  :global([data-dropdown-menu-item][data-highlighted]) .iface-circle.free {
    border-color: #aeb1c8;
  }

  :global(.iface-gap) {
    width: 20px;
    margin-right: 0.3rem;
    flex: none;
  }
</style>
