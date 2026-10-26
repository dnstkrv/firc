import { expect, test } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

test.describe("Feedback Components", () => {
  let groupsPage: GroupsPage;

  test.beforeEach(async ({ page }) => {
    groupsPage = new GroupsPage(page);
    await signedIn(page);
    await page.route("**/groups?with_rules=true", async (route) =>
      route.fulfill({ json: { groups: [] } }),
    );
    await page.route("**/interfaces", async (route) => route.fulfill({ json: { interfaces: [] } }));
    await groupsPage.goto();
  });

  test("should show toast on success", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);

    await page.route("**/groups?save=true", async (route) => {
      await route.fulfill({ status: 200, json: {} });
    });

    await groupsPage.setGroupName(0, "G");
    await groupsPage.setRulePattern(0, 0, "p");

    await groupsPage.save();

    const toast = page.getByText("Saved");
    await expect(toast).toBeVisible();
  });

  // Catches a toast squeezed to half the phone width, leaving a word alone on its last line.
  test("a short toast keeps one line on a 360 px phone", async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 760 });
    await page.evaluate(() =>
      dispatchEvent(
        new CustomEvent("toast", {
          detail: { content: "Конфиг импортирован: 1", type: "success" },
        }),
      ),
    );
    const content = page.locator(".toast .content");
    await expect(content).toBeVisible();
    const lines = await content.evaluate((el) => {
      const range = document.createRange();
      range.selectNodeContents(el);
      return new Set([...range.getClientRects()].map((r) => Math.round(r.top))).size;
    });
    expect(lines).toBe(1);
    const box = (await page.locator(".toast").boundingBox())!;
    expect(box.x).toBeGreaterThanOrEqual(8);
    expect(box.x + box.width).toBeLessThanOrEqual(352);
  });

  // Catches a toast that can only wait out its timer: a tap, a sideways or an upward swipe must take it away, a short drag must not.
  test("a toast goes away on a tap or a swipe", async ({ page }) => {
    await page.clock.install();
    await groupsPage.goto();
    await page.clock.pauseAt(Date.now() + 1000);
    const show = (content: string) =>
      page.evaluate(
        (c) => dispatchEvent(new CustomEvent("toast", { detail: { content: c, type: "info" } })),
        content,
      );
    const toast = page.locator(".toast");
    const drag = async (dx: number, dy: number) => {
      const box = (await toast.boundingBox())!;
      const x = box.x + box.width / 2;
      const y = box.y + box.height / 2;
      await page.mouse.move(x, y);
      await page.mouse.down();
      await page.mouse.move(x + dx / 2, y + dy / 2);
      await page.mouse.move(x + dx, y + dy);
      await page.mouse.up();
    };
    await show("one");
    await expect(toast).toHaveCount(1);
    await toast.click();
    await expect(toast).toHaveCount(0);
    await show("two");
    await drag(120, 0);
    await expect(toast).toHaveCount(0);
    await show("three");
    await drag(0, -80);
    await expect(toast).toHaveCount(0);
    await show("four");
    await drag(20, 0);
    await expect(toast).toHaveCount(1);
    await page.clock.runFor(3500);
    await expect(toast).toHaveCount(0);
  });

  test("should show overlay on loading", async ({ page }) => {
    await groupsPage.createGroup();
    await groupsPage.addRuleToGroup(0);
    await groupsPage.setGroupName(0, "G");
    await groupsPage.setRulePattern(0, 0, "p");

    await page.route("**/groups?save=true", async (route) => {
      await page.waitForTimeout(500);
      await route.fulfill({ status: 200, json: {} });
    });

    const savePromise = groupsPage.save();

    const overlay = page.locator(".overlay");
    await expect(overlay).toBeVisible();

    await savePromise;

    await expect(overlay).toBeHidden();
  });
});
