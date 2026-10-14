<script lang="ts">
  import Kbd from "../../components/ui/Kbd.svelte";
  import { tooltip } from "./tooltip.svelte";
</script>

{#if tooltip.visible}
  <div
    id="global-tooltip"
    role="tooltip"
    class="tooltip-content"
    class:with-keys={tooltip.keys.length > 0}
    style:left="{tooltip.x}px"
    style:top="{tooltip.y}px"
    style:opacity={tooltip.opacity}
  >
    {tooltip.text}
    {#if tooltip.keys.length > 0}<Kbd keys={tooltip.keys} />{/if}
  </div>
{/if}

<style>
  .tooltip-content {
    position: fixed;
    z-index: 15;
    pointer-events: none;
    background-color: var(--bg-dark);
    color: var(--text);
    border: 1px solid var(--bg-light-extra);
    padding: 0.2rem 0.5rem;
    border-radius: 0.5rem;
    font-size: smaller;
    white-space: nowrap;
    transition: opacity 0.1s ease-out;
  }

  .tooltip-content.with-keys {
    display: inline-flex;
    align-items: center;
    gap: 0.9rem;
  }

  @media (hover: none), (pointer: coarse) {
    .tooltip-content,
    .tooltip-content.with-keys {
      display: none;
    }
  }
</style>
