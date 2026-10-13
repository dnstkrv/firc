<script lang="ts">
  import "./app.css";

  import AuthPage from "./components/AuthPage.svelte";
  import AppLayout from "./components/layout/AppLayout.svelte";
  import { token } from "./data/auth.svelte";
  import { fetchInterfaces } from "./data/interfaces.svelte";
  import TooltipLayer from "./lib/tooltip/TooltipLayer.svelte";
  import { loadUpdate } from "./modules/settings/update.svelte";

  import { UPDATE_POLL_MS } from "./modules/settings/update";

  $effect(() => {
    if (token.current) {
      fetchInterfaces();
    }
  });

  $effect(() => {
    if (!token.current) return;
    void loadUpdate();
    const timer = setInterval(() => void loadUpdate(), UPDATE_POLL_MS);
    return () => clearInterval(timer);
  });
</script>

{#if !token.current}
  <AuthPage />
{:else}
  <AppLayout />
{/if}

<TooltipLayer />
