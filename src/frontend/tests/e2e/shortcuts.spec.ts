import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";

async function setup(page: Page) {
  await signedIn(page);
  await page.route("**/interfaces", (route) =>
    route.fulfill({ json: { interfaces: [{ id: "wg0" }, { id: "nwg0" }] } }),
  );
  await page.route("**/system/resolvers", (route) => route.fulfill({ json: { resolvers: [] } }));
  await page.route("**/system/hosts", (route) => route.fulfill({ json: { hosts: [] } }));
  await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
  await page.route(/\/groups(\?.*)?$/, (route) =>
    route.fulfill({
      json: {
        groups: [
          {
            id: "0a000012",
            name: "Plain",
            enable: true,
            interface: "wg0",
            devices: { allow: [], deny: [] },
            resolve: { tunnel: true, server: "" },
            rules: [],
            live: true,
          },
        ],
      },
    }),
  );
  await page.goto("/");
  await expect(page.locator(".group")).toHaveCount(1);
}

const sheetButton = (page: Page) => page.getByRole("button", { name: "Keyboard shortcuts" });
const sheet = (page: Page) => page.locator(".shortcuts-sheet");
const tooltip = (page: Page) => page.locator("#global-tooltip");
const searchKeys = (page: Page) => page.locator(".search-keys");
const caps = (scope: ReturnType<Page["locator"]>) => scope.locator("kbd");

test.describe("Keyboard shortcut hints", () => {
  test.beforeEach(async ({ page }) => {
    await setup(page);
  });

  // Catches a cheat sheet that does not open from its button, lists the wrong shortcuts, or ignores Esc.
  test("the header button opens the cheat sheet with every shortcut and Esc closes it", async ({
    page,
  }) => {
    await sheetButton(page).click();
    await expect(sheet(page)).toBeVisible();
    await expect(sheet(page).locator(".shortcuts-title")).toHaveText("Keyboard shortcuts");
    const rows = sheet(page).locator(".shortcut-row");
    await expect(rows).toHaveCount(5);
    await expect(rows.nth(0)).toContainText("Save");
    await expect(caps(rows.nth(0))).toHaveText(["Ctrl", "S"]);
    await expect(caps(rows.nth(1))).toHaveText(["Ctrl", "F"]);
    await expect(caps(rows.nth(2))).toHaveText(["Ctrl", "Enter"]);
    await expect(caps(rows.nth(3))).toHaveText(["Shift", "Enter"]);
    await expect(caps(rows.nth(4))).toHaveText(["Esc"]);
    await expect(caps(sheet(page).locator(".shortcuts-note"))).toHaveText(["?"]);
    await page.keyboard.press("Escape");
    await expect(sheet(page)).toHaveCount(0);
  });

  // Catches a cheat sheet that stays open after a click elsewhere on the page.
  test("a click outside closes the cheat sheet", async ({ page }) => {
    await sheetButton(page).click();
    await expect(sheet(page)).toBeVisible();
    await page.mouse.click(20, 700);
    await expect(sheet(page)).toHaveCount(0);
  });

  // Catches a ? key that does not toggle the cheat sheet both ways.
  test("the ? key opens and closes the cheat sheet", async ({ page }) => {
    await page.keyboard.press("?");
    await expect(sheet(page)).toBeVisible();
    await page.keyboard.press("?");
    await expect(sheet(page)).toHaveCount(0);
  });

  // Catches a ? key handler that steals the character typed into a field.
  test("a ? typed in the search field stays in the field", async ({ page }) => {
    await page.keyboard.press("Control+f");
    await page.keyboard.press("?");
    await expect(page.locator(".search-input")).toHaveValue("?");
    await expect(sheet(page)).toHaveCount(0);
  });

  // Catches a ? key that opens the cheat sheet over an open dialog.
  test("the ? key does nothing while a dialog is open", async ({ page }) => {
    await page.locator(".info button").click();
    await expect(page.locator("[data-dialog-content]")).toBeVisible();
    await page.keyboard.press("?");
    await expect(sheet(page)).toHaveCount(0);
  });

  // Catches a save tooltip that lost its label or its key-caps.
  test("the save tooltip shows Ctrl S", async ({ page }) => {
    await page.locator("#save-changes").hover();
    await expect(tooltip(page)).toContainText("Save Changes");
    await expect(caps(tooltip(page))).toHaveText(["Ctrl", "S"]);
  });

  // Catches a collapsed search with no hint, or a hint left over the open field.
  test("the collapsed search names Ctrl F and the open one does not", async ({ page }) => {
    await page.locator(".search-container").hover();
    await expect(tooltip(page)).toContainText("Search");
    await expect(caps(tooltip(page))).toHaveText(["Ctrl", "F"]);
    await page.keyboard.press("Control+f");
    await expect(page.locator(".search-input")).toBeFocused();
    await expect(tooltip(page)).toHaveCount(0);
    await page.mouse.move(600, 700);
    await page.locator(".search-container").hover();
    await expect(page.locator(".search-input")).toBeFocused();
    await expect(tooltip(page)).toHaveCount(0);
  });

  // Catches key-caps that sit over typed text in the search field.
  test("the search key-caps show in the empty field and hide once it has text", async ({
    page,
  }) => {
    await page.keyboard.press("Control+f");
    await expect(searchKeys(page)).toBeVisible();
    await expect(caps(searchKeys(page))).toHaveText(["Ctrl", "F"]);
    await expect(searchKeys(page)).toHaveAttribute("aria-hidden", "true");
    await page.keyboard.type("a");
    await expect(searchKeys(page)).toBeHidden();
  });

  // Catches a picker footer that lost the Shift Enter line.
  test("the picker footer names Shift Enter", async ({ page }) => {
    await page.locator(".group .iface-select [data-select-trigger]").first().click();
    const keys = page.locator("[data-select-content] .iface-keys");
    await expect(keys).toBeVisible();
    await expect(caps(keys)).toHaveText(["Shift", "Enter"]);
    await expect(keys).toContainText("add or remove a backup");
  });

  // Catches an import button whose tooltip does not name Ctrl Enter.
  test("the import rules button shows Ctrl Enter", async ({ page }) => {
    await page.locator('[data-value="Import Rule List"] button').click();
    const dialog = page.locator("[data-dialog-content]");
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: "Import", exact: true }).hover();
    await expect(caps(tooltip(page))).toHaveText(["Ctrl", "Enter"]);
  });
});

test.describe("Keyboard shortcut hints on a phone", () => {
  test.use({ hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });

  // Catches hints for a keyboard a touch-only device does not have.
  test("the header button, the search key-caps and the picker line are hidden", async ({
    page,
  }) => {
    await setup(page);
    const button = page.locator(".keys button");
    await expect(button).toHaveCount(1);
    await expect(button).toBeHidden();
    await page.locator(".search-container").tap();
    await expect(page.locator(".search-input")).toBeFocused();
    await expect(searchKeys(page)).toHaveCount(1);
    await expect(searchKeys(page)).toBeHidden();
    await page.locator(".group .iface-select [data-select-trigger]").first().tap();
    await expect(page.locator("[data-select-content] .iface-footer")).toBeVisible();
    const keys = page.locator("[data-select-content] .iface-keys");
    await expect(keys).toHaveCount(1);
    await expect(keys).toBeHidden();
  });
});

test.describe("Keyboard shortcut hints on a narrow window", () => {
  test.use({ viewport: { width: 360, height: 760 } });

  // Catches the Ctrl F key-caps taking room in the phone-width search field.
  test("the search key-caps are hidden", async ({ page }) => {
    await setup(page);
    await page.locator(".search-container").click();
    await expect(page.locator(".search-input")).toBeFocused();
    await expect(searchKeys(page)).toHaveCount(1);
    await expect(searchKeys(page)).toBeHidden();
  });
});
