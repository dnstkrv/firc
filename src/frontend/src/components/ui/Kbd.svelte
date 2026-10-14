<script lang="ts">
  let { keys, class: className = "" }: { keys: string[]; class?: string } = $props();
</script>

<span class="kbd {className}">
  {#each keys as key}<kbd>{key}</kbd>{/each}
</span>

<style>
  .kbd {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    flex: none;
  }

  kbd {
    display: inline-block;
    min-width: 1.4em;
    box-sizing: border-box;
    padding: 2px 5px 1px;
    font: 600 11px/1.2 var(--font);
    text-align: center;
    color: var(--text);
    background: #23253a;
    border: 1px solid #3a3d55;
    border-bottom-width: 2px;
    border-radius: 4px;
  }
</style>
