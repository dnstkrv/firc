<script lang="ts">
  import { onDestroy, setContext, type Snippet } from "svelte";

  import { hide, show } from "../../lib/tooltip/tooltip.svelte";

  import { TOOLTIP_LABEL } from "./tooltip-label";

  let {
    value,
    keys = [],
    children,
  }: { value: string; keys?: string[]; children: Snippet } = $props();
  let triggerEl: HTMLElement;

  let shown = $state(false);
  let pressed = false;

  setContext(TOOLTIP_LABEL, () => value);

  $effect(() => {
    if (shown) show(triggerEl, value, keys);
  });

  function open() {
    if (!pressed) shown = true;
  }

  function close() {
    if (shown) hide(triggerEl);
    shown = false;
  }

  function press() {
    pressed = true;
    close();
  }

  function leave() {
    pressed = false;
    close();
  }

  function focus(event: FocusEvent) {
    if ((event.target as Element).matches(":focus-visible")) open();
  }

  onDestroy(close);
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  bind:this={triggerEl}
  data-value={value}
  style:display="inline-flex"
  aria-describedby={shown ? "global-tooltip" : undefined}
  onpointerenter={open}
  onpointerleave={leave}
  onpointerdown={press}
  onfocusin={focus}
  onfocusout={close}
>
  {@render children()}
</div>
