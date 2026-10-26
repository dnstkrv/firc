import { expect, test } from "@playwright/test";

import { signedIn } from "./pages/session";

test.describe("Header Settings", () => {
  test.beforeEach(async ({ page }) => {
    await signedIn(page);
    await page.route("**/groups?with_rules=true", async (route) =>
      route.fulfill({ json: { groups: [] } }),
    );
    await page.route("**/interfaces", async (route) => route.fulfill({ json: { interfaces: [] } }));
    await page.goto("/");
  });

  // Catches a phone menu that hides which page is open, cannot be dismissed by a tap outside, or leaves its backdrop behind.
  test("on a phone the menu names the page and a tap outside closes it", async ({ page }) => {
    await page.setViewportSize({ width: 400, height: 760 });
    const button = page.locator(".mobile-dropdown-btn");
    await expect(page.locator(".mobile-title")).toHaveText("Groups");
    await button.click();
    await expect(button).toHaveAttribute("aria-expanded", "true");
    await page.mouse.click(380, 700);
    await expect(button).toHaveAttribute("aria-expanded", "false");
    await expect(page.locator(".menu-backdrop")).toHaveCount(0);
    await button.click();
    await page.getByRole("tab", { name: "Journal" }).click();
    await expect(page.locator(".mobile-title")).toHaveText("Journal");
    await expect(button).toHaveAttribute("aria-expanded", "false");
  });

  // Catches a long version drawn over the Russian nav tabs, or the dev badge back next to it.
  for (const width of [1290, 1024]) {
    test(`a long version stays clear of the nav tabs at ${width} px`, async ({ page }) => {
      await page.evaluate(() => localStorage.setItem("locale", JSON.stringify({ value: "ru" })));
      await page.setViewportSize({ width, height: 600 });
      await page.reload();
      await expect(page.getByRole("tab").last()).toHaveText("Настройки");
      await expect(page.getByText("dev", { exact: true })).toHaveCount(0);
      const version = page.locator(".version .version-text");
      await version.evaluate(
        (el) => (el.textContent = "0.3.1~git20261016154241.805abcd (805abcd)"),
      );
      const v = await version.boundingBox();
      const tab = await page.getByRole("tab").last().boundingBox();
      expect(v && tab).toBeTruthy();
      const apart = v!.x >= tab!.x + tab!.width || v!.x + v!.width <= tab!.x;
      expect(apart).toBe(true);
      expect(v!.width).toBeGreaterThan(0);
    });
  }

  test("should display version", async ({ page }) => {
    const version = page.locator(".version .version-text");
    await expect(version).toBeVisible();
    expect(version.textContent.length).toBeGreaterThan(0);
  });

  test("should rotate locale", async ({ page }) => {
    const localeBtn = page.locator(".locale button");

    const initialText = await localeBtn.textContent();

    await localeBtn.click();

    await expect(localeBtn).not.toHaveText(initialText || "");

    await localeBtn.click();
  });

  test("should open info dialog", async ({ page }) => {
    const infoBtn = page.locator(".info button");
    await expect(infoBtn).toBeVisible();

    await infoBtn.click();

    const dialog = page.locator("[data-dialog-content]");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("About", { exact: true })).toBeVisible();

    await expect(dialog.locator("text=Repository")).toBeVisible();
    await expect(dialog.locator("text=Bug Tracker")).toBeVisible();
    await expect(dialog.locator('a[href="https://github.com/hoaxisr/firc"]')).toBeVisible();
    await expect(dialog.getByRole("link", { name: "https://firc.hoaxisr.ru" })).toHaveAttribute(
      "href",
      "https://firc.hoaxisr.ru",
    );

    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
  });
});
