import { expect, test } from "@playwright/test";

import { answer, CLASSES, openSettings } from "./pages/settings";

// Catches rows under the wrong heading, an uncounted change, or a restart setting not marked waiting.
test("the saved values show, with nothing counted as changed", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await expect(page.getByRole("textbox", { name: "Upstream DNS", exact: true })).toHaveValue(
    "127.0.0.1",
  );
  await expect(page.getByRole("spinbutton", { name: "Query timeout" })).toHaveValue("5000");
  await expect(page.getByRole("switch", { name: "Drop AAAA" })).toHaveAttribute(
    "aria-checked",
    "true",
  );
  await expect(page.getByTestId("settings-counter")).toHaveText("0 settings changed");
});

// Catches the log level row or its section left on the page after the daemon dropped the setting.
test("there is no log level to set", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await expect(page.getByRole("switch", { name: "Drop AAAA" })).toBeVisible();
  await expect(page.getByText("Log level")).toHaveCount(0);
  await expect(page.locator('[data-row="app.logLevel"]')).toHaveCount(0);
  await expect(page.locator('[data-section="journal"]')).toHaveCount(0);
});

test("there is no fake PTR switch", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await expect(page.getByRole("switch", { name: "Drop AAAA" })).toBeVisible();
  await expect(page.getByText("PTR")).toHaveCount(0);
  await expect(page.locator('[data-row="app.dnsProxy.disableFakePTR"]')).toHaveCount(0);
});

// Catches rows filed by the WebUI's own list instead of the classes the daemon sends.
test("rows are filed under the class the daemon gives them", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  const dns = page.locator('[data-section="dns"]');
  await expect(dns.locator('[data-group="live"]').getByText("Upstream DNS").first()).toBeVisible();
  await expect(dns.locator('[data-group="restart"]').getByText("Query timeout")).toBeVisible();
  await expect(dns.getByText("After a daemon restart")).toBeVisible();
  await expect(page.locator('[data-section="netfilter"] header')).toContainText(
    "The whole section applies after a restart",
  );
  await expect(page.locator('[data-section="dns"] header')).not.toContainText(
    "The whole section applies after a restart",
  );
});

test("a class the daemon changes moves the row", async ({ page }) => {
  const classes = { ...CLASSES, "app.dnsProxy.timeout": "live" };
  await openSettings(page, (r) => r.fulfill({ json: answer({}, [], classes) }));
  await expect(
    page.locator('[data-section="dns"] [data-group="live"]').getByText("Query timeout"),
  ).toBeVisible();
});

// Catches a missed edit in the counter, a border before any change, or a Reset leaving a field edited.
test("edits are counted and bordered, and Reset puts every one back", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  const upstream = page.getByRole("textbox", { name: "Upstream DNS", exact: true });
  const names = page.getByRole("spinbutton", { name: "Domains in the pool, at most" });
  await expect(upstream).not.toHaveClass(/changed/);
  await upstream.fill("1.1.1.1");
  await expect(page.getByTestId("settings-counter")).toHaveText("1 setting changed");
  await expect(upstream).toHaveClass(/changed-live/);
  await names.fill("4096");
  await expect(page.getByTestId("settings-counter")).toHaveText("2 settings changed");
  await expect(names).toHaveClass(/changed-restart/);
  await page.getByRole("button", { name: "Reset" }).click();
  await expect(page.getByTestId("settings-counter")).toHaveText("0 settings changed");
  await expect(upstream).toHaveValue("127.0.0.1");
  await expect(names).toHaveValue("65536");
  await expect(upstream).not.toHaveClass(/changed/);
});

// Catches a pending restart setting not marked, a live one marked, or a miscounting banner.
test("settings waiting for a restart are marked and counted", async ({ page }) => {
  await openSettings(page, (r) =>
    r.fulfill({
      json: answer({ "app.addressPool.maxNames": 4096 }, ["app.addressPool.maxNames", "app.link"]),
    }),
  );
  await expect(page.getByTestId("settings-banner")).toContainText("2 settings wait for a restart");
  await expect(page.locator('[data-row="app.addressPool.maxNames"]')).toContainText(
    "waits for a restart",
  );
  await expect(page.locator('[data-row="app.dnsProxy.upstream.address"]')).not.toContainText(
    "waits for a restart",
  );
});

test("there is no banner when nothing waits", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await expect(page.getByTestId("settings-banner")).toHaveCount(0);
});

// Catches loading only on mount, so a change made on the daemon is never seen (bits-ui mounts all tabs at start).
test("switching back to Settings reloads, so a change made while away is seen", async ({
  page,
}) => {
  let served = answer();
  await openSettings(page, (r) => r.fulfill({ json: served }));
  await page.getByRole("tab", { name: "Groups" }).click();
  served = answer({ "app.addressPool.maxNames": 4096 }, ["app.addressPool.maxNames"]);
  await page.getByRole("tab", { name: "Settings" }).click();
  await expect(page.getByRole("spinbutton", { name: "Domains in the pool, at most" })).toHaveValue(
    "4096",
  );
  await expect(page.getByTestId("settings-banner")).toContainText("1 setting waits for a restart");
});

// Catches a reload on tab activation overwriting an unsaved draft.
test("an unsaved edit survives switching tabs away and back", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  const upstream = page.getByRole("textbox", { name: "Upstream DNS", exact: true });
  await upstream.fill("1.1.1.1");
  await page.getByRole("tab", { name: "Groups" }).click();
  await page.getByRole("tab", { name: "Settings" }).click();
  await expect(upstream).toHaveValue("1.1.1.1");
  await expect(page.getByTestId("settings-counter")).toHaveText("1 setting changed");
});

// Catches an edit typed during a slow reload being discarded when the answer lands.
test("an edit made while a reload is in flight survives the answer landing", async ({ page }) => {
  let releaseSecond: () => void = () => {};
  const secondDelay = new Promise<void>((resolve) => {
    releaseSecond = resolve;
  });
  let requests = 0;
  await openSettings(page, async (r) => {
    requests += 1;
    if (requests === 1) {
      await r.fulfill({ json: answer() });
      return;
    }
    await secondDelay;
    await r.fulfill({ json: answer({}, ["app.addressPool.maxNames"]) });
  });
  await page.getByRole("tab", { name: "Groups" }).click();
  await page.getByRole("tab", { name: "Settings" }).click();
  const upstream = page.getByRole("textbox", { name: "Upstream DNS", exact: true });
  await upstream.fill("1.1.1.1");
  releaseSecond();
  await expect(page.getByTestId("settings-banner")).toContainText("1 setting waits for a restart");
  await expect(page.locator('[data-row="app.addressPool.maxNames"]')).toContainText(
    "waits for a restart",
  );
  await expect(upstream).toHaveValue("1.1.1.1");
  await expect(page.getByTestId("settings-counter")).toHaveText("1 setting changed");
});

// Catches a reload keeping the whole draft, so a key saved elsewhere shows stale and is written back.
test("a key saved elsewhere arrives under an edit, and only the edit counts", async ({ page }) => {
  let releaseSecond: () => void = () => {};
  const secondDelay = new Promise<void>((resolve) => {
    releaseSecond = resolve;
  });
  let requests = 0;
  await openSettings(page, async (r) => {
    requests += 1;
    if (requests === 1) {
      await r.fulfill({ json: answer() });
      return;
    }
    await secondDelay;
    await r.fulfill({
      json: answer({ "app.addressPool.maxNames": 4096 }, ["app.addressPool.maxNames"]),
    });
  });
  await page.getByRole("tab", { name: "Groups" }).click();
  await page.getByRole("tab", { name: "Settings" }).click();
  const upstream = page.getByRole("textbox", { name: "Upstream DNS", exact: true });
  const names = page.getByRole("spinbutton", { name: "Domains in the pool, at most" });
  await upstream.fill("1.1.1.1");
  releaseSecond();
  await expect(page.getByTestId("settings-banner")).toContainText("1 setting waits for a restart");
  await expect(names).toHaveValue("4096");
  await expect(names).not.toHaveClass(/changed/);
  await expect(upstream).toHaveValue("1.1.1.1");
  await expect(page.getByTestId("settings-counter")).toHaveText("1 setting changed");
});

// Catches one Russian form for every number (1, 2 and 5 take different forms).
test("Russian counts agree with the number", async ({ page }) => {
  const five = [
    "app.addressPool.maxNames",
    "app.link",
    "app.dnsProxy.timeout",
    "app.addressPool.ttlClamp",
    "app.addressPool.v4.pool",
  ];
  await openSettings(page, (r) => r.fulfill({ json: answer({}, five) }), { locale: "ru" });
  await expect(page.getByTestId("settings-banner")).toContainText("5 настроек ждут перезапуска");
  await page.getByRole("textbox", { name: "Вышестоящий DNS", exact: true }).fill("1.1.1.1");
  await expect(page.getByTestId("settings-counter")).toHaveText("Изменена 1 настройка");
  await page.getByRole("spinbutton", { name: "Таймаут запроса" }).fill("2500");
  await expect(page.getByTestId("settings-counter")).toHaveText("Изменены 2 настройки");
});

// Catches a chip without its description, the segments not offered first, a search blind to other interfaces, or a tunnel or the blackhole offered.
test("the LAN picker offers the segments and finds any other interface", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  const row = page.locator('[data-row="app.link"]');
  await expect(row.locator(".tag")).toHaveText(["Home network"]);
  await expect(row.locator(".tag")).toHaveAttribute("title", "br0");
  await row.getByRole("button", { name: "Add" }).click();
  const search = row.getByRole("combobox", { name: "Search interface" });
  await expect(search).toBeFocused();
  await expect(row.locator(".section")).toHaveText("Segments");
  const offered = row.getByRole("listbox", { name: "LAN interfaces" }).getByRole("option");
  await expect(offered).toHaveText([/^\s*Home network\s*br0\s*$/, /^\s*Guest\s*br1\s*$/]);
  await expect(offered.first()).toHaveAttribute("aria-selected", "true");
  await offered.filter({ hasText: "br1" }).click();
  await expect(row.locator(".tag")).toHaveText(["Home network", "Guest"]);
  await search.fill("eth2");
  await expect(row.locator(".section")).toHaveCount(0);
  await expect(offered).toHaveText([/^\s*eth2\.1\s*$/]);
  await search.press("ArrowDown");
  await search.press("Enter");
  await expect(row.locator(".tag")).toHaveText(["Home network", "Guest", "eth2.1"]);
  await search.fill("vless");
  await expect(offered).toHaveCount(0);
  await search.fill("eth9");
  await expect(row.locator(".panel .empty")).toHaveText("Enter adds it as typed");
  await search.press("Enter");
  await expect(row.locator(".tag")).toHaveText(["Home network", "Guest", "eth2.1", "eth9"]);
  await search.press("Escape");
  await expect(search).toHaveCount(0);
  await expect(row.getByRole("button", { name: "Add" })).toBeFocused();
});

// Catches Enter ignoring a typed match until an arrow key, or Tab leaving the panel open behind.
test("Enter takes the first match and Tab closes the LAN panel", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  const row = page.locator('[data-row="app.link"]');
  await row.getByRole("button", { name: "Add" }).click();
  const search = row.getByRole("combobox", { name: "Search interface" });
  await search.fill("ppp");
  await search.press("Enter");
  await expect(row.locator(".tag")).toHaveText(["Home network", "Broadband"]);
  await search.press("Tab");
  await expect(search).toHaveCount(0);
});

// Catches the LAN panel spilling past a phone's screen once the row wraps.
test("the LAN panel fits a 360 px phone", async ({ page }) => {
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await page.setViewportSize({ width: 360, height: 800 });
  const row = page.locator('[data-row="app.link"]');
  await row.getByRole("button", { name: "Add" }).click();
  const box = await row.locator(".panel").boundingBox();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(360);
});

test("the interface check shows its four fields and saves the interval as a live change", async ({
  page,
}) => {
  const puts: unknown[] = [];
  await openSettings(page, async (route) => {
    if (route.request().method() === "PUT") {
      puts.push(route.request().postDataJSON());
      await route.fulfill({ json: { applied: ["app.check.interval"], pendingRestart: [] } });
      return;
    }
    await route.fulfill({ json: answer() });
  });
  const section = page.locator('[data-section="check"]');
  await expect(section.locator("header")).toContainText("Interface check");
  await expect(section.getByRole("textbox", { name: "Check URL", exact: true })).toHaveValue(
    "http://cp.cloudflare.com/generate_204",
  );
  await expect(section.getByRole("textbox", { name: "WAN check URL" })).toHaveValue("");
  await expect(section.getByRole("spinbutton", { name: "Check timeout" })).toHaveValue("5");
  const interval = section.getByRole("spinbutton", { name: "Check interval" });
  await expect(interval).toHaveValue("30");
  await interval.fill("45");
  await page.getByRole("button", { name: "Save", exact: true }).click();

  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Applies at once")).toBeVisible();
  await expect(dialog.getByText("Needs a daemon restart")).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Save and restart" })).toHaveCount(0);
  await expect(dialog.locator('[data-key="app.check.interval"] .now')).toHaveText("45 s");
  await dialog.getByRole("button", { name: "Save", exact: true }).click();

  await expect(page.getByRole("dialog")).toBeHidden();
  expect(puts).toEqual([{ settings: { "app.check.interval": 45 } }]);
});

const YANDEX = "http://api.browser.yandex.ru/generate_204";

test("the Yandex chip fills the WAN check URL, a save sends it, clearing sends an empty string", async ({
  page,
}) => {
  // Catches the chip filling another key, a draft never marked changed, or a clear that sends nothing.
  const puts: unknown[] = [];
  let wan = "";
  await openSettings(page, async (route) => {
    if (route.request().method() === "PUT") {
      const body = route.request().postDataJSON();
      puts.push(body);
      wan = body.settings["app.check.wanUrl"];
      await route.fulfill({ json: { applied: ["app.check.wanUrl"], pendingRestart: [] } });
      return;
    }
    await route.fulfill({ json: answer({ "app.check.wanUrl": wan }) });
  });
  const section = page.locator('[data-section="check"]');
  const field = section.getByRole("textbox", { name: "WAN check URL" });
  await expect(field).toHaveAttribute("placeholder", "same as the check URL");
  await expect(section.getByRole("textbox", { name: "Check URL", exact: true })).toHaveValue(
    "http://cp.cloudflare.com/generate_204",
  );
  await section.getByRole("button", { name: "Yandex" }).click();
  await expect(field).toHaveValue(YANDEX);
  await expect(field).toHaveClass(/changed-live/);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeHidden();
  expect(puts).toEqual([{ settings: { "app.check.wanUrl": YANDEX } }]);

  await page.reload();
  await expect(field).toHaveValue(YANDEX);
  await field.fill("");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeHidden();
  expect(puts[1]).toEqual({ settings: { "app.check.wanUrl": "" } });
});

test("the Yandex chip stays inside a 390 px phone", async ({ page }) => {
  // Catches the chip wrapping or being pushed past the screen edge by the field.
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await page.setViewportSize({ width: 390, height: 800 });
  const chip = page
    .locator('[data-row="app.check.wanUrl"]')
    .getByRole("button", { name: "Yandex" });
  const box = await chip.boundingBox();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(390);
});

test("the save dialog keeps a long URL inside its row on a 390 px phone", async ({ page }) => {
  // Catches the new value pushed past the row's edge or drawn over the setting's name.
  await openSettings(page, (r) => r.fulfill({ json: answer() }));
  await page.setViewportSize({ width: 390, height: 800 });
  await page
    .locator('[data-row="app.check.wanUrl"]')
    .getByRole("button", { name: "Yandex" })
    .click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  const row = page.getByRole("dialog").locator('[data-key="app.check.wanUrl"]');
  const rowBox = (await row.boundingBox())!;
  const name = (await row.locator(".name").boundingBox())!;
  const values = (await row.locator(".now").boundingBox())!;
  expect(values.x + values.width).toBeLessThanOrEqual(rowBox.x + rowBox.width);
  const apart = name.y + name.height <= values.y || name.x + name.width <= values.x;
  expect(apart).toBe(true);
});

const CLOUDFLARE = "http://cp.cloudflare.com/generate_204";

test("the Cloudflare chip puts the default check URL back and a save sends it", async ({
  page,
}) => {
  // Catches the chip filling another key, another URL, or a draft never marked changed.
  const puts: unknown[] = [];
  await openSettings(page, async (route) => {
    if (route.request().method() === "PUT") {
      puts.push(route.request().postDataJSON());
      await route.fulfill({ json: { applied: ["app.check.url"], pendingRestart: [] } });
      return;
    }
    await route.fulfill({ json: answer({ "app.check.url": "http://example.com/204" }) });
  });
  const section = page.locator('[data-section="check"]');
  const field = section.getByRole("textbox", { name: "Check URL", exact: true });
  await expect(field).toHaveValue("http://example.com/204");
  await section.getByRole("button", { name: "Cloudflare" }).click();
  await expect(field).toHaveValue(CLOUDFLARE);
  await expect(field).toHaveClass(/changed-live/);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeHidden();
  expect(puts).toEqual([{ settings: { "app.check.url": CLOUDFLARE } }]);
});

for (const width of [320, 360, 390, 414, 768, 1024, 1280, 1920]) {
  test(`both check chips sit beside their fields inside a ${width} px screen`, async ({ page }) => {
    // Catches a chip pushed off the screen, drawn over its field, or the page scrolling sideways.
    await openSettings(page, (r) => r.fulfill({ json: answer() }));
    await page.setViewportSize({ width, height: 900 });
    for (const [key, name] of [
      ["app.check.url", "Cloudflare"],
      ["app.check.wanUrl", "Yandex"],
    ]) {
      const row = page.locator(`[data-row="${key}"]`);
      const chip = (await row.getByRole("button", { name }).boundingBox())!;
      const input = (await row.getByRole("textbox").boundingBox())!;
      expect(chip.x).toBeGreaterThanOrEqual(0);
      expect(chip.x + chip.width).toBeLessThanOrEqual(width);
      expect(input.x + input.width).toBeLessThanOrEqual(width);
      const apart = input.x + input.width <= chip.x || input.y + input.height <= chip.y;
      expect(apart).toBe(true);
    }
    const scroll = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(scroll).toBeLessThanOrEqual(width);
  });
}
