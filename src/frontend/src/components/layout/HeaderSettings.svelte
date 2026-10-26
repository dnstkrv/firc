<script lang="ts">
  import { token } from "../../data/auth.svelte";
  import { locale, locales, t } from "../../data/locale.svelte";
  import UpdatePopover from "../../modules/settings/UpdatePopover.svelte";
  import InfoDialog from "../InfoDialog.svelte";
  import Button from "../ui/Button.svelte";
  import Tooltip from "../ui/Tooltip.svelte";
  import ShortcutsSheet from "./ShortcutsSheet.svelte";

  import { Info, Locale, LogOut } from "../ui/icons";

  const version = import.meta.env.VITE_PKG_VERSION || "0.0.0";

  let infoIsOpen = $state(false);

  const rotateLocale = () => {
    const keys = Object.keys(locales);
    const idx = keys.indexOf(locale.current);
    locale.current = keys[(idx + 1) % keys.length];
  };
  const flag = (key: string) => (key === "en" ? "🇺🇸" : key === "ru" ? "🇷🇺" : key);

  function logout() {
    token.reset();
  }
</script>

<div class="container">
  <div class="version">
    <UpdatePopover {version} />
  </div>

  <div class="keys">
    <ShortcutsSheet />
  </div>

  <div class="info">
    <Tooltip value={t("About this app")}>
      <Button small onclick={() => (infoIsOpen = true)}>
        <div class="info-content">
          <Info size={16} />
          <span class="info-label">{t("About")}</span>
        </div>
      </Button>
    </Tooltip>
  </div>

  <div class="locale">
    <Tooltip value={t("Change Locale")}>
      <Button small onclick={rotateLocale}>
        <div class="locale-content">
          <Locale size={16} />
          {flag(locale.current)}
        </div>
      </Button>
    </Tooltip>
  </div>

  <div class="logout">
    <Tooltip value={t("Logout")}>
      <Button small onclick={logout}>
        <LogOut size={20} />
      </Button>
    </Tooltip>
  </div>
</div>

<InfoDialog bind:open={infoIsOpen} />

<style>
  .container {
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 0.8rem;
    min-width: 0;
    flex: 1;
  }

  .version {
    display: flex;
    align-items: center;
    flex: 1;
    min-width: 0;
  }

  .keys,
  .locale,
  .logout,
  .info {
    display: flex;
    flex-direction: row;
    align-items: center;
    flex: 0 0 auto;
  }

  .locale,
  .logout {
    gap: 1rem;
  }

  .logout :global(button),
  .locale :global(button),
  .info :global(button) {
    background: var(--bg-light);
    border-radius: 0.5rem;
    height: 35px;
  }

  .locale :global(button) {
    width: 55px;
  }

  .locale-content,
  .info-content {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 1rem;
    line-height: 1;
  }

  .info-content {
    font-size: 0.85rem;
  }

  @media (hover: none) {
    .keys {
      display: none;
    }
  }

  @media (max-width: 960px) {
    .info-label {
      display: none;
    }
  }

  @media (max-width: 700px) {
    .keys {
      display: none;
    }

    .locale,
    .logout {
      gap: 0.5rem;
    }

    .container {
      gap: 0.4rem;
    }

    .info :global(button) {
      min-width: 34px;
    }
  }
</style>
