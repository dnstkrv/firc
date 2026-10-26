import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";
import { answer, openSettings, upToDate } from "./pages/settings";

const newer = {
  ...upToDate,
  check: {
    ...upToDate.check,
    ageS: 0,
    latest: {
      ...upToDate.check.latest,
      version: "0.3.0",
      tag: "0.3.0",
      publishedAt: "2026-10-12T10:00:00Z",
      asset: { name: "firc_0.3.0-1_entware_mipsel-3.4_kn.ipk", size: 830000 },
    },
    newer: true,
  },
};

const unchecked = { ...upToDate, check: null };

const settingsAnswer = async (route: Parameters<Parameters<Page["route"]>[1]>[0]) =>
  route.fulfill({ json: answer() });

const popover = (page: Page) => page.locator(".update-popover");

async function openPopover(page: Page) {
  if ((await popover(page).count()) === 0) await page.locator(".version-button").click();
  await expect(popover(page)).toBeVisible();
  return page.getByTestId("update-status");
}

async function closePopover(page: Page) {
  await page.keyboard.press("Escape");
  await expect(popover(page)).toHaveCount(0);
}

// Catches a popover that shows nothing until somebody presses Check, or a check spent on loading the page.
test("opening the popover with nothing cached checks", async ({ page }) => {
  let posts = 0;
  await openSettings(page, settingsAnswer, {
    onUpdate: (r) => r.fulfill({ json: unchecked }),
    onCheck: (r) => {
      posts++;
      return r.fulfill({ json: newer });
    },
  });
  await expect(page.locator('[data-section="updates"]')).toBeVisible();
  await page.waitForTimeout(300);
  expect(posts).toBe(0);
  const status = await openPopover(page);
  await expect(status).toHaveText(/Install 0\.3\.0/);
  await page.waitForTimeout(300);
  expect(posts).toBe(1);
});

// Catches the installed build's target missing from the popover, or a separator left for an empty one.
test("the popover names the installed build and its target", async ({ page }) => {
  let target = "mipsel-3.4_kn";
  await openSettings(page, settingsAnswer, {
    onUpdate: (r) =>
      r.fulfill({ json: { ...upToDate, installed: { ...upToDate.installed, target } } }),
  });
  await openPopover(page);
  await expect(page.getByTestId("update-build")).toHaveText("0.2.0 · mipsel-3.4_kn");
  await closePopover(page);
  target = "";
  await openPopover(page);
  await expect(page.getByTestId("update-build")).toHaveText("0.2.0");
});

// Catches a status read started during a check landing after it and putting the old answer back.
test("a status read during a check does not undo its result", async ({ page }) => {
  let posts = 0;
  let gets = 0;
  await openSettings(page, settingsAnswer, {
    onUpdate: async (r) => {
      gets++;
      if (gets === 3) await new Promise((done) => setTimeout(done, 1500));
      await r.fulfill({ json: unchecked });
    },
    onCheck: async (r) => {
      posts++;
      await new Promise((done) => setTimeout(done, 800));
      await r.fulfill({ json: newer });
    },
  });
  await expect.poll(() => gets).toBe(1);
  const status = await openPopover(page);
  await expect.poll(() => posts).toBe(1);
  await expect(page.getByTestId("update-check")).toBeDisabled();
  await closePopover(page);
  await openPopover(page);
  await expect(status).toHaveText(/Install 0\.3\.0/);
  await expect.poll(() => gets).toBe(3);
  await page.waitForTimeout(1800);
  await expect(status).toHaveText(/Install 0\.3\.0/);
  await expect(page.getByTestId("update-dot")).toBeVisible();
  expect(posts).toBe(1);
});

// Catches a second check started when the popover is opened again while one is under way.
test("re-opening the popover during a check does not start a second one", async ({ page }) => {
  let posts = 0;
  let answered = 0;
  await openSettings(page, settingsAnswer, {
    onUpdate: (r) => r.fulfill({ json: unchecked }),
    onCheck: async (r) => {
      posts++;
      await new Promise((done) => setTimeout(done, 1000));
      await r.fulfill({ json: newer });
      answered++;
    },
  });
  await openPopover(page);
  await expect.poll(() => posts).toBe(1);
  await closePopover(page);
  const status = await openPopover(page);
  await expect.poll(() => answered).toBe(1);
  await expect(status).toHaveText(/Install 0\.3\.0/);
  await page.waitForTimeout(300);
  expect(posts).toBe(1);
});

// Catches every open of the popover spending one of GitHub's 60 requests an hour.
test("a fresh check is not repeated on opening the popover", async ({ page }) => {
  let posts = 0;
  await openSettings(page, settingsAnswer, {
    onCheck: (r) => {
      posts++;
      return r.fulfill({ json: upToDate });
    },
  });
  const status = await openPopover(page);
  await expect(status).toContainText("checked 0 min ago");
  await closePopover(page);
  await openPopover(page);
  await expect(status).toContainText("Latest version");
  await page.waitForTimeout(300);
  expect(posts).toBe(0);
});

test.describe("rate limit", () => {
  test.use({ timezoneId: "UTC", locale: "en-GB" });

  // Catches a 429 shown as a bare failure, without the time GitHub takes checks again.
  test("a rate limited check says when to try again", async ({ page }) => {
    await openSettings(page, settingsAnswer, {
      onUpdate: (r) => r.fulfill({ json: unchecked }),
      onCheck: (r) =>
        r.fulfill({
          status: 429,
          json: {
            error: "GitHub refuses more checks from this address until 2026-10-12T19:01:29Z",
            resetAt: 1791831689,
          },
        }),
    });
    const status = await openPopover(page);
    await expect(status).toContainText("Check failed");
    await expect(status).toContainText("try again after 19:01");
    expect(await page.locator(".toast").count()).toBe(0);
  });
});

// Catches a 502 shown without GitHub's reason, or Check left disabled after a failure.
test("a failed check shows the daemon's reason and can be repeated", async ({ page }) => {
  let posts = 0;
  await openSettings(page, settingsAnswer, {
    onUpdate: (r) => r.fulfill({ json: unchecked }),
    onCheck: (r) => {
      posts++;
      return r.fulfill({ status: 502, json: { error: "Could not resolve host: api.github.com" } });
    },
  });
  const status = await openPopover(page);
  await expect(status.locator(".sub")).toHaveText("Could not resolve host: api.github.com");
  await page.getByTestId("update-check").click();
  await expect.poll(() => posts).toBe(2);
});

// Catches a status read that toasts, so a daemon without its checker nags on every page.
test("an update checker that is not running stays quiet", async ({ page }) => {
  let gets = 0;
  await openSettings(page, settingsAnswer, {
    onUpdate: (r) => {
      gets++;
      return r.fulfill({ status: 503, json: { error: "the update checker is not running" } });
    },
  });
  await expect(page.locator('[data-section="updates"]')).toBeVisible();
  await page.locator(".version-button").click();
  await expect(popover(page)).toContainText("No answer from the daemon");
  await expect.poll(() => gets).toBeGreaterThanOrEqual(2);
  await expect(page.getByTestId("update-status")).toHaveCount(0);
  expect(await page.locator(".toast").count()).toBe(0);
});

// Catches the dot missing for a newer release until somebody opens Settings.
test("the header dot shows a newer release", async ({ page }) => {
  await signedIn(page);
  await page.route("**/groups?with_rules=true", (r) => r.fulfill({ json: { groups: [] } }));
  await page.route("**/interfaces", (r) => r.fulfill({ json: { interfaces: [] } }));
  await page.route("**/system/update", (r) => r.fulfill({ json: newer }));
  await page.goto("/");
  await expect(page.getByTestId("update-dot")).toBeVisible();
  await expect(page.locator('[data-section="updates"]')).toBeHidden();
});

// Catches the dot shown for a build that is up to date.
test("the header dot stays away when the build is up to date", async ({ page }) => {
  await openSettings(page, settingsAnswer);
  const status = await openPopover(page);
  await expect(status).toContainText("Latest version");
  await expect(page.getByTestId("update-dot")).toHaveCount(0);
});

// Catches the daily check missing from the catalogue, filed as a restart setting, or sent as a string.
test("the daily check switch saves as a live setting", async ({ page }) => {
  const puts: unknown[] = [];
  await openSettings(page, async (route) => {
    if (route.request().method() === "PUT") {
      puts.push(route.request().postDataJSON());
      await route.fulfill({ json: { applied: ["app.update.check"], pendingRestart: [] } });
      return;
    }
    await route.fulfill({ json: answer() });
  });
  const daily = page.getByRole("switch", { name: "Check for updates daily" });
  await expect(daily).toHaveAttribute("aria-checked", "false");
  await daily.click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Applies at once")).toBeVisible();
  await expect(dialog.getByText("Needs a daemon restart")).toHaveCount(0);
  await dialog.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeHidden();
  expect(puts).toEqual([{ settings: { "app.update.check": true } }]);
  await expect(page.getByTestId("settings-banner")).toHaveCount(0);
});

type Mode =
  | "offer"
  | "downloading"
  | "installing"
  | "502"
  | "404"
  | "503"
  | "drop"
  | "new"
  | "not-landed"
  | "stale"
  | "failed";

type Answered = Exclude<Mode, "502" | "404" | "503" | "drop">;
type RouteOf = Parameters<Parameters<Page["route"]>[1]>[0];

const installed030 = {
  ...upToDate,
  installed: { ...upToDate.installed, version: "0.3.0" },
  check: { ...newer.check, newer: false },
  result: { version: "0.3.0", opkgExit: 0, finishedAt: 1791832000, log: "" },
};

const answers: Record<Answered, unknown> = {
  offer: newer,
  downloading: { ...newer, state: "downloading", progress: { bytes: 414000, total: 829104 } },
  installing: { ...newer, state: "installing" },
  new: installed030,
  "not-landed": {
    ...newer,
    state: "idle",
    result: {
      version: "0.3.0",
      opkgExit: 255,
      finishedAt: 1791832000,
      log: "opkg: cannot install firc",
    },
  },
  stale: {
    ...newer,
    state: "idle",
    result: { version: "0.2.5", opkgExit: 0, finishedAt: 1791800000, log: "" },
  },
  failed: {
    ...newer,
    state: "failed",
    error: "checksum: the package does not match the release",
  },
};

function serveUpdate(mode: { value: Mode }, served: Mode[] = []) {
  return (r: RouteOf) => {
    const now = mode.value;
    served.push(now);
    if (now === "502" || now === "drop") {
      if (now === "drop") mode.value = "downloading";
      return r.fulfill({ status: 502, body: "" });
    }
    if (now === "404") return r.fulfill({ status: 404, json: { error: "not found" } });
    if (now === "503")
      return r.fulfill({ status: 503, json: { error: "the update checker is not running" } });
    return r.fulfill({ json: answers[now] });
  };
}

async function offerInstall(
  page: Page,
  mode: { value: Mode },
  onInstall: (r: RouteOf) => Promise<void> | void,
  opts: {
    served?: Mode[];
    onSettings?: (r: RouteOf) => Promise<void>;
    onRestart?: (r: RouteOf) => Promise<void>;
  } = {},
) {
  await openSettings(page, opts.onSettings ?? settingsAnswer, {
    onUpdate: serveUpdate(mode, opts.served),
    onInstall,
    onRestart: opts.onRestart,
  });
  const install = await openPopover(page);
  await expect(install).toHaveAttribute("data-state", "action");
  return install;
}

const confirmInstall = (page: Page) =>
  page.getByRole("alertdialog").getByRole("button", { name: "Install" }).click();

const accept = (mode: { value: Mode }, next: Mode, bodies: unknown[] = []) => {
  return (r: Parameters<Parameters<Page["route"]>[1]>[0]) => {
    bodies.push(r.request().postDataJSON());
    mode.value = next;
    return r.fulfill({
      status: 202,
      json: { version: "0.3.0", asset: "firc_0.3.0-1_entware_mipsel-3.4_kn.ipk", size: 829104 },
    });
  };
};

// Catches a one-click outage: Install sent without asking first.
test("install_asks_first_and_cancel_sends_nothing", async ({ page }) => {
  const mode = { value: "offer" as Mode };
  const bodies: unknown[] = [];
  const install = await offerInstall(page, mode, accept(mode, "downloading", bodies));
  await install.click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
  await page.waitForTimeout(300);
  expect(bodies).toEqual([]);
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0);
});

// Catches a confirm that hides the outage or that pending settings land with the install.
test("the_confirm_says_dns_stops_and_pending_settings_apply", async ({ page }) => {
  const mode = { value: "offer" as Mode };
  const bodies: unknown[] = [];
  const install = await offerInstall(page, mode, accept(mode, "downloading", bodies));
  await install.click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("Install 0.3.0?");
  await expect(dialog).toContainText(
    "DNS, the WebUI and every tunnel stop for the restart, tens of seconds on mipsel. Settings saved and waiting for a restart take effect.",
  );
  await dialog.getByRole("button", { name: "Install" }).click();
  await expect.poll(() => bodies).toEqual([{ version: "0.3.0" }]);
});

// Catches progress not shown, no overlay for the restart, or a page left on the old bundle.
test("install_shows_progress_then_the_overlay_then_reloads_on_the_new_version", async ({
  page,
}) => {
  const mode = { value: "offer" as Mode };
  const install = await offerInstall(page, mode, accept(mode, "downloading"));
  await install.click();
  await confirmInstall(page);
  const status = await openPopover(page);
  await expect(status).toContainText("49 %");
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0);
  await expect(page.getByTestId("update-check")).toBeDisabled();
  await expect(status).toBeDisabled();
  await expect(status).toHaveAttribute("data-state", "busy");
  mode.value = "installing";
  const overlay = page.getByTestId("restart-overlay");
  await expect(overlay).toBeVisible({ timeout: 5000 });
  mode.value = "502";
  await expect(overlay.getByRole("status")).toContainText("Waiting for it to start…", {
    timeout: 5000,
  });
  await expect(overlay).toBeVisible();
  const load = page.waitForEvent("load", { timeout: 10000 });
  mode.value = "new";
  await load;
});

// Catches an install that did not land reloaded as done, or opkg's exit hidden.
test("an_install_that_did_not_land_says_opkgs_exit", async ({ page }) => {
  const mode = { value: "offer" as Mode };
  let loads = 0;
  const install = await offerInstall(page, mode, accept(mode, "installing"));
  page.on("load", () => loads++);
  await install.click();
  await confirmInstall(page);
  const overlay = page.getByTestId("restart-overlay");
  await expect(overlay).toBeVisible({ timeout: 5000 });
  mode.value = "not-landed";
  await expect(overlay).toHaveAttribute("data-failed", "true", { timeout: 5000 });
  await expect(overlay.getByRole("status")).toContainText("255");
  await page.waitForTimeout(1500);
  expect(loads).toBe(0);
  await expect(overlay).toBeVisible();
});

// Catches a failed download hidden, taken for a restart, or the install not offered again.
test("a_failed_download_shows_its_error_and_no_overlay", async ({ page }) => {
  const mode = { value: "offer" as Mode };
  const bodies: unknown[] = [];
  const install = await offerInstall(page, mode, accept(mode, "failed", bodies));
  await install.click();
  await confirmInstall(page);
  const status = await openPopover(page);
  await expect(status).toContainText("The install failed");
  await expect(status).toContainText("checksum: the package does not match the release");
  await page.waitForTimeout(1500);
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0);
  await expect(status).toHaveAttribute("data-state", "failed");
  await expect(page.getByTestId("update-check")).toBeEnabled();
  const retry = page.getByTestId("update-retry");
  await expect(retry).toHaveText("Install 0.3.0");
  await expect(retry).toBeEnabled();
  await retry.click();
  await expect(page.getByRole("alertdialog")).toContainText("Install 0.3.0?");
  await confirmInstall(page);
  await expect.poll(() => bodies).toEqual([{ version: "0.3.0" }, { version: "0.3.0" }]);
});

// Catches the overlay drawn only on the Settings tab, so an install from another tab never shows its restart.
test("an_install_from_the_groups_tab_shows_the_overlay_and_reloads", async ({ page }) => {
  const mode = { value: "offer" as Mode };
  await signedIn(page);
  await page.route("**/groups?with_rules=true", (r) => r.fulfill({ json: { groups: [] } }));
  await page.route("**/interfaces", (r) => r.fulfill({ json: { interfaces: [] } }));
  await page.route("**/system/update", serveUpdate(mode));
  await page.route("**/system/update/install", accept(mode, "installing"));
  await page.goto("/");
  await expect(page.getByRole("tab", { name: "Groups" })).toHaveAttribute("data-state", "active");
  const install = await openPopover(page);
  await install.click();
  await confirmInstall(page);
  const overlay = page.getByTestId("restart-overlay");
  await expect(overlay).toBeVisible({ timeout: 5000 });
  await expect(page.getByRole("tab", { name: "Groups" })).toHaveAttribute("data-state", "active");
  const load = page.waitForEvent("load", { timeout: 5000 });
  mode.value = "new";
  await load;
});

// Catches Install offered to a build the daemon says cannot install.
test("a_dev_build_offers_no_install", async ({ page }) => {
  await openSettings(page, settingsAnswer, {
    onUpdate: (r) => r.fulfill({ json: { ...newer, canInstall: false, reason: "dev-build" } }),
  });
  const status = await openPopover(page);
  await expect(status).toContainText("A development build does not update itself");
  await expect(page.getByTestId("update-check")).toBeVisible();
  await expect(status).toHaveAttribute("data-state", "idle");
  await expect(status).toBeDisabled();
});

// Catches a refused install that says nothing, or shows the overlay anyway.
test("a_409_from_install_says_why", async ({ page }) => {
  const mode = { value: "offer" as Mode };
  const install = await offerInstall(page, mode, (r) =>
    r.fulfill({ status: 409, json: { error: "a restart is under way" } }),
  );
  await install.click();
  await confirmInstall(page);
  await expect(page.locator(".toast")).toContainText("a restart is under way");
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0);
  const status = await openPopover(page);
  await expect(status).toHaveAttribute("data-state", "action");
  await expect(status).toBeEnabled();
});

// Catches an install sent mid-check, which the daemon refuses with 409.
test("install_waits_while_a_check_runs", async ({ page }) => {
  let release = () => {};
  const held = new Promise<void>((done) => (release = done));
  let checks = 0;
  await openSettings(page, settingsAnswer, {
    onUpdate: (r) => r.fulfill({ json: newer }),
    onCheck: async (r) => {
      checks++;
      await held;
      await r.fulfill({ json: newer });
    },
  });
  const install = await openPopover(page);
  await expect(install).toHaveAttribute("data-state", "action");
  await page.getByTestId("update-check").click();
  await expect.poll(() => checks).toBe(1);
  await expect(install).toBeDisabled();
  await install.click({ force: true });
  await expect(page.getByRole("alertdialog")).toHaveCount(0);
  release();
  await expect(install).toHaveAttribute("data-state", "action");
  await expect(install).toBeEnabled();
});

// Catches one dropped poll mid-download ending in "Not installed" while the download goes on.
test("a_dropped_poll_mid_download_keeps_following", async ({ page }) => {
  const mode = { value: "offer" as Mode };
  const served: Mode[] = [];
  const install = await offerInstall(page, mode, accept(mode, "downloading"), { served });
  await install.click();
  await confirmInstall(page);
  const status = await openPopover(page);
  await expect(status).toContainText("49 %");
  mode.value = "drop";
  await expect
    .poll(() => {
      const at = served.indexOf("drop");
      return at < 0 ? [] : served.slice(at);
    })
    .toEqual(["drop", "downloading", "downloading"]);
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0);
  await expect(page.getByText("Not installed")).toHaveCount(0);
  await expect(status).toContainText("49 %");
  mode.value = "installing";
  await expect(page.getByTestId("restart-overlay")).toBeVisible({ timeout: 5000 });
  await expect(page.getByTestId("restart-overlay")).toHaveAttribute("data-failed", "false");
});

// Catches an earlier install's opkg exit shown as this one's.
test("an_older_result_is_not_this_installs_exit", async ({ page }) => {
  const mode = { value: "offer" as Mode };
  const install = await offerInstall(page, mode, accept(mode, "installing"));
  await install.click();
  await confirmInstall(page);
  const overlay = page.getByTestId("restart-overlay");
  await expect(overlay).toBeVisible({ timeout: 5000 });
  mode.value = "stale";
  await expect(overlay.getByRole("status")).toHaveText("Not installed", {
    timeout: 5000,
  });
});

for (const [name, status] of [
  ["a_daemon_without_the_route_reloads", "404"],
  ["a_daemon_whose_checker_is_off_reloads", "503"],
] as const) {
  // Catches a daemon that answers without a status waited out to the limit.
  test(name, async ({ page }) => {
    const mode = { value: "offer" as Mode };
    const install = await offerInstall(page, mode, accept(mode, "installing"));
    await install.click();
    await confirmInstall(page);
    await expect(page.getByTestId("restart-overlay")).toBeVisible({ timeout: 5000 });
    const load = page.waitForEvent("load", { timeout: 5000 });
    mode.value = status;
    await load;
  });
}

// Catches a failed install of an older release named as failed after a newer one was installed by hand.
test("an_older_releases_result_is_not_shown", async ({ page }) => {
  await openSettings(page, settingsAnswer, {
    onUpdate: (r) =>
      r.fulfill({
        json: {
          ...installed030,
          result: { version: "0.2.0", opkgExit: 255, finishedAt: 1791800000, log: "" },
        },
      }),
  });
  const status = await openPopover(page);
  await expect(page.getByTestId("update-build")).toContainText("0.3.0");
  await expect(status).toContainText("Latest version");
  await expect(status).not.toContainText("not installed");
  await expect(page.getByTestId("update-dot")).toHaveCount(0);
});

// Catches a page opened mid-install that freezes its progress and offers Install again.
test("a_page_opened_mid_install_follows_it", async ({ page }) => {
  const mode = { value: "downloading" as Mode };
  await openSettings(page, settingsAnswer, { onUpdate: serveUpdate(mode) });
  const status = await openPopover(page);
  await expect(status).toContainText("49 %");
  await expect(status).toHaveAttribute("data-state", "busy");
  await expect(status).toBeDisabled();
  mode.value = "installing";
  await expect(page.getByTestId("restart-overlay")).toBeVisible({ timeout: 5000 });
  const load = page.waitForEvent("load", { timeout: 5000 });
  mode.value = "new";
  await load;
});

// Catches a restart offered during an install, which the daemon refuses.
test("restart_waits_while_an_install_runs", async ({ page }) => {
  const mode = { value: "downloading" as Mode };
  await openSettings(page, (r) => r.fulfill({ json: answer({}, ["app.link"]) }), {
    onUpdate: serveUpdate(mode),
  });
  const status = await openPopover(page);
  await expect(status).toContainText("49 %");
  await closePopover(page);
  await expect(
    page.getByTestId("settings-banner").getByRole("button", { name: "Restart" }),
  ).toHaveClass(/inactive/);
  await page.getByRole("spinbutton", { name: "Query timeout" }).fill("4000");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(
    page.getByRole("dialog").getByRole("button", { name: "Save and restart" }),
  ).toBeDisabled();
});

// Catches the daemon's install 409 to a restart shown as "the restart did not start".
test("restart_during_a_download_says_an_update_is_being_installed", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer({}, ["app.link"]) }), {
    onRestart: (r) => r.fulfill({ status: 409, json: { error: "an update is being installed" } }),
  });
  await page.getByTestId("settings-banner").getByRole("button", { name: "Restart" }).click();
  await expect(page.locator(".toast")).toContainText("an update is being installed");
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0);
});

// Catches Check left live between the install's 202 and the first progress answer.
test("check_waits_once_an_install_is_accepted", async ({ page }) => {
  let release = () => {};
  const held = new Promise<void>((done) => (release = done));
  let accepted = false;
  let checks = 0;
  await openSettings(page, settingsAnswer, {
    onUpdate: async (r) => {
      if (accepted) await held;
      await r.fulfill({ json: accepted ? answers.downloading : newer });
    },
    onCheck: (r) => {
      checks++;
      return r.fulfill({ json: newer });
    },
    onInstall: (r) => {
      accepted = true;
      return r.fulfill({ status: 202, json: { version: "0.3.0", asset: "x.ipk", size: 829104 } });
    },
  });
  const install = await openPopover(page);
  await install.click();
  await confirmInstall(page);
  await expect.poll(() => accepted).toBe(true);
  const status = await openPopover(page);
  const check = page.getByTestId("update-check");
  await expect(check).toBeDisabled();
  await check.click({ force: true });
  release();
  await expect(status).toContainText("49 %");
  expect(checks).toBe(0);
});

// Catches a progress poll that misses the installing phase and leaves the page on the old bundle.
test("a_poll_that_misses_installing_still_reloads", async ({ page }) => {
  const mode = { value: "offer" as Mode };
  const install = await offerInstall(page, mode, accept(mode, "downloading"));
  await install.click();
  await confirmInstall(page);
  const status = await openPopover(page);
  await expect(status).toContainText("49 %");
  const load = page.waitForEvent("load", { timeout: 5000 });
  mode.value = "new";
  await load;
});

type Step = "downloading" | "installing" | "new" | "502" | "401";

async function scripted(page: Page, steps: Step[], after: Step) {
  const served: Step[] = [];
  let accepted = false;
  await openSettings(page, settingsAnswer, {
    onUpdate: (r) => {
      if (!accepted) return r.fulfill({ json: newer });
      const now = steps.shift() ?? after;
      served.push(now);
      if (now === "502") return r.fulfill({ status: 502, body: "" });
      if (now === "401") return r.fulfill({ status: 401, json: { error: "Unauthorized" } });
      return r.fulfill({ json: answers[now] });
    },
    onInstall: (r) => {
      accepted = true;
      return r.fulfill({ status: 202, json: { version: "0.3.0", asset: "x.ipk", size: 829104 } });
    },
  });
  const install = await openPopover(page);
  await install.click();
  await confirmInstall(page);
  return served;
}

// Catches a daemon gone before any poll saw installing leaving the page on the old bundle.
test("downloading_then_the_daemon_goes_away_hands_over", async ({ page }) => {
  const served = await scripted(page, ["downloading", "502", "502", "502", "502"], "new");
  const load = page.waitForEvent("load", { timeout: 10000 });
  await expect(page.getByTestId("restart-overlay")).toBeVisible({ timeout: 6000 });
  await load;
  expect(served.slice(0, 4)).toEqual(["downloading", "502", "502", "502"]);
});

// Catches failed polls counted across an answer, handing over in the middle of a download.
test("failures_between_answers_do_not_hand_over", async ({ page }) => {
  const served = await scripted(page, ["502", "downloading", "502", "502"], "downloading");
  await expect.poll(() => served.length, { timeout: 8000 }).toBeGreaterThanOrEqual(6);
  await expect(page.getByTestId("restart-overlay")).toHaveCount(0);
  const status = await openPopover(page);
  await expect(status).toContainText("49 %");
});

for (const [name, before] of [
  ["a_401_during_the_download_stops_following", ["downloading"]],
  ["a_401_during_the_overlay_stops_following", ["installing"]],
] as const) {
  // Catches a logout mid-install polled on, or taken for a dropped poll and shown as the overlay.
  test(name, async ({ page }) => {
    const served = await scripted(page, [...before], "401");
    await expect(page.locator("#login")).toBeVisible({ timeout: 6000 });
    await expect.poll(() => served.length).toBeGreaterThanOrEqual(before.length + 1);
    const seen = served.length;
    await page.waitForTimeout(2500);
    expect(served.length).toBe(seen);
    await expect(page.getByTestId("restart-overlay")).toHaveCount(0);
  });
}

// Catches a second follow loop started by a status read during an install, doubling the polls.
test("reopening_the_popover_mid_install_follows_once", async ({ page }) => {
  let gets = 0;
  await openSettings(page, settingsAnswer, {
    onUpdate: (r) => {
      gets++;
      return r.fulfill({ json: answers.downloading });
    },
  });
  const status = await openPopover(page);
  await expect(status).toContainText("49 %");
  for (let i = 0; i < 3; i++) {
    await closePopover(page);
    await openPopover(page);
  }
  await page.waitForTimeout(500);
  const start = gets;
  await page.waitForTimeout(4000);
  expect(gets - start).toBeLessThanOrEqual(5);
});

// Catches the reloaded page left on "Installing…", or the stale check not run once it settles.
test("a_reloaded_page_that_lands_mid_install_settles", async ({ page }) => {
  const settled = { ...installed030, check: null };
  let state = "installing";
  let checks = 0;
  await openSettings(page, (r) => r.fulfill({ json: answer({}, ["app.link"]) }), {
    onUpdate: (r) => r.fulfill({ json: { ...settled, state } }),
    onCheck: (r) => {
      checks++;
      return r.fulfill({ json: installed030 });
    },
  });
  const restart = page.getByTestId("settings-banner").getByRole("button", { name: "Restart" });
  const status = await openPopover(page);
  await expect(status).toContainText("Installing…");
  await expect(restart).toHaveClass(/inactive/);
  state = "idle";
  await expect(status).toContainText("Latest version", { timeout: 5000 });
  await expect(restart).not.toHaveClass(/inactive/);
  expect(checks).toBe(1);
});
