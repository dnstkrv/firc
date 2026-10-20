import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

const SINCE = new Date(2026, 9, 14, 18, 28).getTime() / 1000;

const STATES = [
  { name: "wg0", state: "dead", since: SINCE, error: "timed out" },
  { name: "nwg0", state: "alive", since: SINCE - 600, error: "" },
];

const base = {
  enable: true,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules: [],
  live: true,
};

const listed = (extra: Record<string, unknown> = {}) => ({
  ...base,
  id: "0a000011",
  name: "Backup",
  interface: ["wg0", "nwg0"],
  active: "nwg0",
  interfaces: STATES,
  ...extra,
});

const plain = (extra: Record<string, unknown> = {}) => ({
  ...base,
  id: "0a000012",
  name: "Plain",
  interface: "wg0",
  ...extra,
});

async function setup(page: Page, groups: Record<string, unknown>[], locale = "en") {
  const daemon = { groups, puts: [] as any[], moveUps: [] as string[] };
  await signedIn(page);
  await page.addInitScript(
    (l) => localStorage.setItem("locale", JSON.stringify({ value: l })),
    locale,
  );
  await page.route("**/interfaces", (route) =>
    route.fulfill({
      json: {
        interfaces: [
          { id: "blackhole" },
          { id: "wg0", name: "WireGuard Interface", role: "tunnel" },
          { id: "nwg0", role: "tunnel" },
          { id: "nwg3", role: "tunnel" },
          { id: "nwg1", role: "tunnel" },
          { id: "nwg2", role: "tunnel" },
        ],
      },
    }),
  );
  await page.route("**/system/resolvers", (route) => route.fulfill({ json: { resolvers: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  await page.route("**/system/config/save", (route) => route.fulfill({ json: {} }));
  await page.route(/\/move-up$/, async (route) => {
    daemon.moveUps.push(new URL(route.request().url()).pathname);
    await route.fulfill({ status: 500, json: { error: "unexpected" } });
  });
  await page.route(/\/groups(\?.*)?$/, async (route) => {
    const request = route.request();
    if (request.method() === "PUT") {
      const body = request.postDataJSON();
      daemon.puts.push(body);
      await route.fulfill({
        json: { groups: body.groups.map((g: any) => ({ ...g, live: true })) },
      });
      return;
    }
    await route.fulfill({ json: { groups: daemon.groups } });
  });
  await page.goto("/");
  await expect(page.locator(".group")).toHaveCount(groups.length);
  return daemon;
}

const picker = (page: Page) => page.locator(".group .iface-select").first();
const closedValue = (page: Page) => picker(page).locator(".selected-value");
const content = (page: Page) => page.locator("[data-select-content]");
const row = (page: Page, id: string) => page.locator(`[data-select-item][data-value="${id}"]`);
const circle = (page: Page, id: string) => page.locator(`[data-circle="${id}"]`);
const footer = (page: Page) => content(page).locator(".iface-footer");
const amber = (page: Page) => picker(page).locator(".iface-amber");

async function openPicker(page: Page) {
  await picker(page).locator("[data-select-trigger]").click();
  await expect(content(page)).toBeVisible();
}

async function save(page: Page, daemon: { puts: any[] }, count: number) {
  await page.locator("#save-changes").click();
  await expect.poll(() => daemon.puts.length).toBe(count);
  return daemon.puts[count - 1].groups[0].interface;
}

test.describe("The interface picker in the card", () => {
  test("a plain group offers a circle on every row but blackhole, and a row click picks it", async ({
    page,
  }) => {
    const daemon = await setup(page, [plain()]);
    await expect(closedValue(page)).toHaveText("WireGuard Interface");
    await expect(amber(page)).toHaveCount(0);
    await openPicker(page);
    await expect(circle(page, "blackhole")).toHaveCount(0);
    for (const id of ["wg0", "nwg0", "nwg3", "nwg1", "nwg2"])
      await expect(row(page, id).locator(`[data-circle="${id}"]`)).toHaveCount(1);
    await expect(circle(page, "wg0")).toHaveText("1");
    await expect(circle(page, "nwg0")).toHaveText("");
    await expect(footer(page)).toHaveText("1 — first, 2–4 — backups in order");
    await row(page, "nwg0").locator(".option-label").click();
    await expect(content(page)).toBeHidden();
    await expect(closedValue(page)).toHaveText("nwg0");
    expect(await save(page, daemon, 1)).toBe("nwg0");
    expect(daemon.moveUps).toEqual([]);
  });

  test("a circle adds a backup without closing, and a second click leaves the group clean", async ({
    page,
  }) => {
    const daemon = await setup(page, [plain()]);
    await openPicker(page);
    await circle(page, "nwg0").click();
    await expect(circle(page, "nwg0")).toHaveText("2");
    await expect(content(page)).toBeVisible();
    await expect(closedValue(page)).toHaveText("WireGuard Interface");
    await expect(page.locator(".group .live-status")).toHaveAttribute("data-kind", "unsaved");
    await expect(page.locator("#save-changes")).not.toHaveClass(/inactive/);
    await circle(page, "nwg0").click();
    await expect(circle(page, "nwg0")).toHaveText("");
    await expect(content(page)).toBeVisible();
    await expect(page.locator(".group .live-status")).toHaveAttribute("data-kind", "live");
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
    await circle(page, "nwg3").click();
    await circle(page, "nwg0").click();
    await expect(circle(page, "nwg3")).toHaveText("2");
    await expect(circle(page, "nwg0")).toHaveText("3");
    await page.keyboard.press("Escape");
    expect(await save(page, daemon, 1)).toEqual(["wg0", "nwg3", "nwg0"]);
    expect(daemon.moveUps).toEqual([]);
  });

  test("a list group loads clean and shows the active entry with the amber dot", async ({
    page,
  }) => {
    await setup(page, [listed()], "ru");
    await expect(page.locator(".group .live-status")).toHaveAttribute("data-kind", "live");
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
    await expect(closedValue(page)).toHaveText("nwg0");
    await amber(page).hover();
    await expect(page.getByRole("tooltip")).toHaveText(
      "Работает резервный nwg0 · основной wg0 не работает с 18:28",
    );
  });

  test("the amber dot names the backup to a screen reader and opens its tooltip on focus", async ({
    page,
  }) => {
    await setup(page, [listed()], "ru");
    const text = "Работает резервный nwg0 · основной wg0 не работает с 18:28";
    await expect(amber(page)).toHaveAttribute("aria-label", text);
    await amber(page).focus();
    await expect(page.getByRole("tooltip")).toHaveText(text);
  });

  test("a plain group's picker opened by keyboard keeps its interface on Enter", async ({
    page,
  }) => {
    const daemon = await setup(page, [plain({ interface: "nwg0" })]);
    await picker(page).locator("[data-select-trigger]").focus();
    await page.keyboard.press("Enter");
    await expect(content(page)).toBeVisible();
    await expect(row(page, "nwg0")).toHaveAttribute("aria-selected", "true");
    await expect(row(page, "nwg0")).toHaveAttribute("data-highlighted", "");
    await page.keyboard.press("Enter");
    await expect(content(page)).toBeHidden();
    await expect(closedValue(page)).toHaveText("nwg0");
    await expect(page.locator(".group .live-status")).toHaveAttribute("data-kind", "live");
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
    expect(daemon.puts).toEqual([]);
  });

  test("a list group's picker opened by keyboard keeps its list on Enter", async ({ page }) => {
    const daemon = await setup(page, [listed()]);
    await picker(page).locator("[data-select-trigger]").focus();
    await page.keyboard.press("Enter");
    await expect(content(page)).toBeVisible();
    await expect(row(page, "wg0")).toHaveAttribute("aria-selected", "true");
    await expect(row(page, "wg0")).toHaveAttribute("data-highlighted", "");
    await page.keyboard.press("Enter");
    await expect(content(page)).toBeHidden();
    await expect(page.locator(".group .live-status")).toHaveAttribute("data-kind", "live");
    await expect(page.locator("#save-changes")).toHaveClass(/inactive/);
    await openPicker(page);
    await expect(circle(page, "nwg0")).toHaveText("2");
    expect(daemon.puts).toEqual([]);
  });

  test("Shift+Enter acts on its own picker, not on another one's highlighted row", async ({
    page,
  }) => {
    await setup(page, [plain(), plain({ id: "0a000013", name: "Other", interface: "nwg3" })]);
    await page.evaluate(() => {
      const stray = document.createElement("div");
      stray.setAttribute("data-select-content", "");
      stray.innerHTML = '<div data-select-item data-highlighted data-value="nwg1"></div>';
      document.body.prepend(stray);
    });
    await picker(page).locator("[data-select-trigger]").click();
    await row(page, "nwg0").hover();
    await expect(row(page, "nwg0")).toHaveAttribute("data-highlighted", "");
    await page.keyboard.press("Shift+Enter");
    await expect(circle(page, "nwg0")).toHaveText("2");
    await expect(circle(page, "nwg1")).toHaveText("");
  });

  test("an active backup with a name shows the name over its id", async ({ page }) => {
    await setup(page, [
      listed({
        interface: ["nwg0", "wg0"],
        active: "wg0",
        interfaces: [
          { name: "nwg0", state: "dead", since: SINCE, error: "timed out" },
          { name: "wg0", state: "alive", since: SINCE - 600, error: "" },
        ],
      }),
    ]);
    await expect(amber(page)).toHaveCount(1);
    await expect(closedValue(page)).toHaveText("WireGuard Interface");
    await expect(picker(page).locator(".selected-description")).toHaveText("wg0");
  });

  test("a list group on its first entry shows no amber dot", async ({ page }) => {
    await setup(page, [listed({ active: "wg0" })]);
    await expect(closedValue(page)).toHaveText("WireGuard Interface");
    await expect(picker(page).locator(".selected-description")).toHaveText("wg0");
    await expect(amber(page)).toHaveCount(0);
  });

  test("an unsaved list shows its own first entry, not the daemon's", async ({ page }) => {
    await setup(page, [listed({ active: "wg0" })]);
    await openPicker(page);
    await circle(page, "wg0").click();
    await expect(circle(page, "nwg0")).toHaveText("1");
    await expect(closedValue(page)).toHaveText("nwg0");
    await circle(page, "nwg3").click();
    await page.keyboard.press("Escape");
    await expect(closedValue(page)).toHaveText("nwg0");
    await expect(amber(page)).toHaveCount(0);
  });

  test("an unsaved list on a backup hides the amber dot", async ({ page }) => {
    await setup(page, [listed()]);
    await expect(amber(page)).toHaveCount(1);
    await openPicker(page);
    await circle(page, "nwg3").click();
    await expect(closedValue(page)).toHaveText("WireGuard Interface");
    await expect(amber(page)).toHaveCount(0);
  });

  test("a list group with every entry down shows no amber dot", async ({ page }) => {
    await setup(page, [listed({ live: false, liveReason: "no-interface" })]);
    await expect(page.locator(".group .live-status")).toHaveAttribute("data-kind", "no-interface");
    await expect(closedValue(page)).toHaveText("nwg0");
    await expect(amber(page)).toHaveCount(0);
  });

  test("the rows keep their states while the list is unsaved", async ({ page }) => {
    await setup(page, [listed()]);
    await openPicker(page);
    await circle(page, "nwg3").click();
    await expect(circle(page, "nwg3")).toHaveText("3");
    await expect(row(page, "wg0").locator(".iface-dot")).toHaveAttribute("data-state", "dead");
    await expect(row(page, "nwg0").locator(".iface-dot")).toHaveAttribute("data-state", "alive");
  });

  test("the circle of a list's first entry removes it and keeps the list open", async ({
    page,
  }) => {
    const daemon = await setup(page, [listed()]);
    await openPicker(page);
    await circle(page, "wg0").click();
    await expect(circle(page, "wg0")).toHaveText("");
    await expect(circle(page, "nwg0")).toHaveText("1");
    await expect(content(page)).toBeVisible();
    await page.keyboard.press("Escape");
    expect(await save(page, daemon, 1)).toBe("nwg0");
  });

  test("each row shows its interface's state", async ({ page }) => {
    await setup(page, [listed()]);
    await openPicker(page);
    await expect(row(page, "wg0").locator(".iface-dot")).toHaveAttribute("data-state", "dead");
    await expect(row(page, "nwg0").locator(".iface-dot")).toHaveAttribute("data-state", "alive");
    await expect(row(page, "nwg3").locator(".iface-dot")).toHaveAttribute("data-state", "unknown");
  });

  test("a row click on a list's first entry collapses the list to it", async ({ page }) => {
    const daemon = await setup(page, [listed()]);
    await openPicker(page);
    await expect(row(page, "wg0").locator(".option-check svg")).toHaveCount(1);
    await expect(row(page, "nwg0").locator(".option-check svg")).toHaveCount(0);
    await row(page, "wg0").locator(".option-label").click();
    await expect(content(page)).toBeHidden();
    expect(await save(page, daemon, 1)).toBe("wg0");
    expect(daemon.moveUps).toEqual([]);
  });

  test("a full list offers no circle on a free row", async ({ page }) => {
    await setup(page, [listed({ interface: ["wg0", "nwg0", "nwg3", "nwg1"], active: "wg0" })]);
    await openPicker(page);
    await expect(circle(page, "nwg1")).toHaveText("4");
    await expect(circle(page, "nwg2")).toHaveCount(0);
    await expect(footer(page)).toBeVisible();
  });

  test("a blackhole group offers no circle and no footer", async ({ page }) => {
    await setup(page, [plain({ interface: "blackhole" })]);
    await openPicker(page);
    await expect(content(page).locator("[data-circle]")).toHaveCount(0);
    await expect(footer(page)).toHaveCount(0);
  });

  test("an active entry gone from the router shows greyed", async ({ page }) => {
    await setup(page, [listed({ interface: ["gone0", "nwg0"], active: "gone0" })]);
    await expect(closedValue(page)).toHaveText("gone0");
    await expect(picker(page)).toHaveClass(/missing/);
  });

  // Catches an active interface outside both the list and the router shown as present.
  test("an active entry outside the list shows greyed", async ({ page }) => {
    await setup(page, [listed({ interface: ["nwg0", "wg0"], active: "gone9" })]);
    await expect(closedValue(page)).toHaveText("gone9");
    await expect(picker(page)).toHaveClass(/missing/);
  });

  // Catches an entry the router lacks left out of the picker, so it can be neither seen nor removed.
  test("a backup gone from the router is a row whose circle removes it", async ({ page }) => {
    await setup(page, [listed({ interface: ["nwg0", "gone0"] })]);
    await openPicker(page);
    await expect(circle(page, "gone0")).toHaveText("2");
    await circle(page, "gone0").click();
    await expect(row(page, "gone0")).toHaveCount(0);
  });

  test("Shift+Enter toggles the highlighted row's circle and keeps the picker open", async ({
    page,
  }) => {
    await setup(page, [plain()]);
    await openPicker(page);
    await expect(row(page, "nwg0")).toHaveAttribute(
      "aria-description",
      "Shift+Enter — add as a backup or remove",
    );
    await row(page, "nwg0").hover();
    await expect(row(page, "nwg0")).toHaveAttribute("data-highlighted", "");
    await page.keyboard.press("Shift+Enter");
    await expect(circle(page, "nwg0")).toHaveText("2");
    await expect(content(page)).toBeVisible();
    await page.keyboard.press("Shift+Enter");
    await expect(circle(page, "nwg0")).toHaveText("");
    await expect(content(page)).toBeVisible();
  });
});

test.describe("The interface picker by touch", () => {
  test.use({ hasTouch: true });

  test("a tapped circle adds a backup and the picker stays open", async ({ page }) => {
    await setup(page, [plain()]);
    await openPicker(page);
    await circle(page, "nwg0").tap();
    await expect(circle(page, "nwg0")).toHaveText("2");
    await expect(content(page)).toBeVisible();
    await expect(closedValue(page)).toHaveText("WireGuard Interface");
  });

  test("a tapped circle of a list's first entry removes it and keeps the list open", async ({
    page,
  }) => {
    const daemon = await setup(page, [listed()]);
    await openPicker(page);
    await circle(page, "wg0").tap();
    await expect(circle(page, "wg0")).toHaveText("");
    await expect(circle(page, "nwg0")).toHaveText("1");
    await expect(content(page)).toBeVisible();
    await page.keyboard.press("Escape");
    expect(await save(page, daemon, 1)).toBe("nwg0");
  });

  test("a tap on a list's first entry collapses the list to it", async ({ page }) => {
    const daemon = await setup(page, [listed()]);
    await openPicker(page);
    await row(page, "wg0").locator(".option-label").tap();
    await expect(content(page)).toBeHidden();
    expect(await save(page, daemon, 1)).toBe("wg0");
  });
});

test.describe("The interface picker in the group dialog", () => {
  const chain = () => listed({ interface: ["wg0", "nwg0", "nwg3"] });
  const field = (page: Page) => page.getByRole("dialog").locator(".interface-select");

  test("keeps Name and Interface side by side and shows the saved chain", async ({ page }) => {
    await setup(page, [chain()]);
    await page.getByRole("button", { name: "Group Settings" }).click();
    const name = await page.locator("#gd-name").boundingBox();
    const iface = await field(page).boundingBox();
    expect(Math.abs(name!.y - iface!.y)).toBeLessThan(4);
    expect(iface!.x).toBeGreaterThan(name!.x + name!.width);
    await expect(field(page).locator(".selected-value")).toHaveText("wg0 → nwg0 → nwg3");
    await expect(field(page).locator(".selected-value [title]")).toHaveAttribute(
      "title",
      "wg0 → nwg0 → nwg3",
    );
  });

  test("the dialog shows the daemon's states on its rows", async ({ page }) => {
    await setup(page, [chain()]);
    await page.getByRole("button", { name: "Group Settings" }).click();
    await field(page).locator("[data-select-trigger]").click();
    await expect(row(page, "wg0").locator(".iface-dot")).toHaveAttribute("data-state", "dead");
    await expect(row(page, "nwg0").locator(".iface-dot")).toHaveAttribute("data-state", "alive");
  });

  test("a circle in the dialog edits the list, and one entry saves as a string", async ({
    page,
  }) => {
    const daemon = await setup(page, [chain()]);
    const dialog = page.getByRole("dialog");
    await page.getByRole("button", { name: "Group Settings" }).click();
    await field(page).locator("[data-select-trigger]").click();
    await circle(page, "nwg3").click();
    await expect(content(page)).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(content(page)).toBeHidden();
    await expect(field(page).locator(".selected-value")).toHaveText("wg0 → nwg0");
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toBeHidden();
    expect(await save(page, daemon, 1)).toEqual(["wg0", "nwg0"]);

    await page.getByRole("button", { name: "Group Settings" }).click();
    await field(page).locator("[data-select-trigger]").click();
    await circle(page, "nwg0").click();
    await page.keyboard.press("Escape");
    await expect(field(page).locator(".selected-value")).toHaveText("WireGuard Interface");
    await expect(field(page).locator(".selected-description")).toHaveText("wg0");
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).toBeHidden();
    expect(await save(page, daemon, 2)).toBe("wg0");
    expect(daemon.moveUps).toEqual([]);
  });
});
