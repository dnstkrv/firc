import { expect, test, type Page } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

type Rule = { id: string; type: string; rule: string; enable: boolean; comment?: string };

const group = (id: string, name: string, rules: Rule[]) => ({
  id,
  name,
  interface: "wg0",
  enable: true,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules,
  live: true,
});

const rule = (id: string, pattern: string, comment?: string): Rule => ({
  id,
  type: "domain",
  rule: pattern,
  enable: true,
  ...(comment === undefined ? {} : { comment }),
});

async function setup(page: Page, groups: ReturnType<typeof group>[]) {
  const daemon = { groups: structuredClone(groups), puts: [] as any[] };
  await signedIn(page);
  await page.route("**/interfaces", (route) =>
    route.fulfill({ json: { interfaces: [{ id: "wg0" }] } }),
  );
  await page.route("**/system/netfilter", (route) => route.fulfill({ json: { ok: true } }));
  await page.route("**/system/config/save", (route) => route.fulfill({ json: {} }));
  await page.route(/\/groups(\?.*)?$/, async (route) => {
    const request = route.request();
    if (request.method() === "PUT") {
      const body = request.postDataJSON();
      daemon.puts.push(body);
      daemon.groups = body.groups.map((g: any) => ({ ...g, live: true }));
      await route.fulfill({ json: { groups: daemon.groups } });
      return;
    }
    const withRules = request.url().includes("with_rules=true");
    await route.fulfill({
      json: { groups: daemon.groups.map(({ rules, ...g }) => (withRules ? { ...g, rules } : g)) },
    });
  });
  const groupsPage = new GroupsPage(page);
  await groupsPage.goto();
  return { daemon, groupsPage };
}

const icon = (page: Page, ruleIndex = 0) =>
  page.locator(".group-wrapper").first().locator(".rule").nth(ruleIndex).locator(".rule-comment");
const editor = (page: Page) => page.locator(".rule-comment-editor");
const status = (page: Page) => page.locator(".group .live-status").first();

const TEXT = 'Meta "CDN" \\ #1: Европа';

test.describe("A rule's comment", () => {
  // Catches the editor not opening, Enter not saving, the icon not turning accent, no tooltip, no unsaved mark, the PUT lacking it, or a reload losing it.
  test("added through the icon, saved and kept across a reload", async ({ page }) => {
    const { daemon, groupsPage } = await setup(page, [
      group("0a000001", "Meta", [rule("0b000001", "a.example.com")]),
    ]);
    await groupsPage.expandGroup(0);

    await expect(icon(page)).toHaveAttribute("aria-label", "Comment");
    await expect(icon(page)).not.toHaveClass(/\bset\b/);
    await icon(page).click();
    const input = editor(page).locator("input");
    await expect(input).toBeFocused();
    await input.fill(TEXT);
    await input.press("Enter");

    await expect(editor(page)).toBeHidden();
    await expect(icon(page)).toHaveClass(/\bset\b/);
    await expect(icon(page)).toHaveAttribute("aria-label", `Comment: ${TEXT}`);
    await expect(status(page)).toHaveAttribute("data-kind", "unsaved");
    await page.mouse.move(0, 0);
    await icon(page).hover();
    await expect(page.getByRole("tooltip")).toHaveText(TEXT);

    await groupsPage.save();
    await expect.poll(() => daemon.puts.length).toBe(1);
    expect(daemon.puts[0].groups[0].rules[0].comment).toBe(TEXT);

    await page.reload();
    await expect(groupsPage.addGroupButton).not.toHaveClass(/inactive/);
    await groupsPage.expandGroup(0);
    await expect(icon(page)).toHaveAttribute("aria-label", `Comment: ${TEXT}`);
    await expect(icon(page)).toHaveClass(/\bset\b/);
  });

  // Catches Esc keeping the draft, or focus not coming back to the icon.
  test("Esc cancels the edit", async ({ page }) => {
    const { groupsPage } = await setup(page, [
      group("0a000001", "G", [rule("0b000001", "a.example.com", "kept")]),
    ]);
    await groupsPage.expandGroup(0);

    await icon(page).click();
    const input = editor(page).locator("input");
    await expect(input).toHaveValue("kept");
    await input.fill("changed");
    await input.press("Escape");

    await expect(editor(page)).toBeHidden();
    await expect(icon(page)).toBeFocused();
    await expect(icon(page)).toHaveAttribute("aria-label", "Comment: kept");
    await expect(status(page)).toHaveAttribute("data-kind", "live");
  });

  // Catches clearing written as "" rather than none: the group stays unsaved.
  test("a comment added and cleared leaves the group clean", async ({ page }) => {
    const { groupsPage } = await setup(page, [
      group("0a000001", "G", [rule("0b000001", "a.example.com")]),
    ]);
    await groupsPage.expandGroup(0);

    await icon(page).click();
    await editor(page).locator("input").fill("x");
    await editor(page).locator("input").press("Enter");
    await expect(status(page)).toHaveAttribute("data-kind", "unsaved");

    await icon(page).click();
    await editor(page).locator("input").fill("  ");
    await editor(page).locator("input").press("Enter");
    await expect(icon(page)).not.toHaveClass(/\bset\b/);
    await expect(status(page)).toHaveAttribute("data-kind", "live");
  });

  // Catches a cleared comment sent as "" or kept in the PUT.
  test("clearing a saved comment sends the rule without one", async ({ page }) => {
    const { daemon, groupsPage } = await setup(page, [
      group("0a000001", "G", [rule("0b000001", "a.example.com", "old")]),
    ]);
    await groupsPage.expandGroup(0);

    await icon(page).click();
    await editor(page).locator("input").fill("");
    await editor(page).locator("input").press("Enter");
    await expect(icon(page)).toHaveAttribute("aria-label", "Comment");

    await groupsPage.save();
    await expect.poll(() => daemon.puts.length).toBe(1);
    expect("comment" in daemon.puts[0].groups[0].rules[0]).toBe(false);
  });

  // Catches a click outside the editor dropping the draft, so Save sends the group without it.
  test("a click on Save outside the editor keeps the typed comment", async ({ page }) => {
    const { daemon, groupsPage } = await setup(page, [
      group("0a000001", "G", [rule("0b000001", "a.example.com")]),
    ]);
    await groupsPage.expandGroup(0);

    await icon(page).click();
    await editor(page).locator("input").fill("typed");
    await groupsPage.save();

    await expect.poll(() => daemon.puts.length).toBe(1);
    expect(daemon.puts[0].groups[0].rules[0].comment).toBe("typed");
    await expect(editor(page)).toBeHidden();
  });

  // Catches a stored comment rewritten by opening and confirming it (inner spaces collapsed).
  test("a stored comment confirmed unchanged leaves the group clean", async ({ page }) => {
    const { groupsPage } = await setup(page, [
      group("0a000001", "G", [rule("0b000001", "a.example.com", "a  b")]),
    ]);
    await groupsPage.expandGroup(0);

    await icon(page).click();
    await expect(editor(page).locator("input")).toHaveValue("a  b");
    await editor(page).locator("input").press("Enter");
    await expect(editor(page)).toBeHidden();
    await expect(icon(page)).toHaveAttribute("aria-label", "Comment: a  b");
    await expect(status(page)).toHaveAttribute("data-kind", "live");
  });

  // Catches Enter that only ends an IME composition closing the editor.
  test("Enter during a composition does not save", async ({ page }) => {
    const { groupsPage } = await setup(page, [
      group("0a000001", "G", [rule("0b000001", "a.example.com")]),
    ]);
    await groupsPage.expandGroup(0);

    await icon(page).click();
    const input = editor(page).locator("input");
    await input.fill("にほん");
    await input.dispatchEvent("keydown", { key: "Enter", isComposing: true, bubbles: true });
    await expect(editor(page)).toBeVisible();
    await expect(input).toBeFocused();
    await input.press("Enter");
    await expect(editor(page)).toBeHidden();
    await expect(icon(page)).toHaveAttribute("aria-label", "Comment: にほん");
  });

  // Catches a comment over 256 bytes let through, or the hint shown before anything was cut.
  test("cuts a long comment to 256 bytes and says so", async ({ page }) => {
    const { groupsPage } = await setup(page, [
      group("0a000001", "G", [rule("0b000001", "a.example.com")]),
    ]);
    await groupsPage.expandGroup(0);

    await icon(page).click();
    const hint = editor(page).getByText("Up to 256 bytes");
    await expect(hint).toHaveCount(0);
    await editor(page).locator("input").fill("я".repeat(130));
    await expect(editor(page).locator("input")).toHaveValue("я".repeat(128));
    await expect(hint).toBeVisible();
    await expect(hint).toHaveAttribute("role", "status");
    const described = await editor(page).locator("input").getAttribute("aria-describedby");
    expect(described).toBeTruthy();
    await expect(page.locator(`#${described}`)).toHaveText("Up to 256 bytes");
  });

  // Catches the comment left out of the search index.
  test("a search finds a rule by its comment", async ({ page }) => {
    const { groupsPage } = await setup(page, [
      group("0a000001", "First", [
        rule("0b000001", "a.example.com", "Meta CDN"),
        rule("0b000002", "b.example.com"),
      ]),
      group("0a000002", "Second", [rule("0b000003", "c.example.com", "other")]),
    ]);

    await groupsPage.search("Meta");
    await expect(page.locator(".group-wrapper:visible")).toHaveCount(1);
    const rows = page.locator(".group-wrapper:visible .rule");
    await expect(rows).toHaveCount(1);
    await expect(rows.locator(".pattern-input")).toHaveValue("a.example.com");
    await expect(rows.locator(".rule-comment")).toHaveAttribute("data-search-match", "true");
  });

  // Catches an edit that leaves the search index stale, so a comment just typed is not found.
  test("a search finds a comment typed after an earlier search", async ({ page }) => {
    const { groupsPage } = await setup(page, [
      group("0a000001", "First", [
        rule("0b000001", "a.example.com"),
        rule("0b000002", "b.example.com"),
      ]),
    ]);
    await groupsPage.expandGroup(0);

    await groupsPage.search("zeta");
    await expect(page.locator(".group-wrapper:visible")).toHaveCount(0);
    await groupsPage.search("");
    await expect(page.locator(".group-wrapper:visible .rule")).toHaveCount(2);

    await icon(page, 1).click();
    await editor(page).locator("input").fill("Zeta");
    await editor(page).locator("input").press("Enter");

    await groupsPage.search("zeta");
    const rows = page.locator(".group-wrapper:visible .rule");
    await expect(rows).toHaveCount(1);
    await expect(rows.locator(".pattern-input")).toHaveValue("b.example.com");
  });
});

test.describe("A rule's comment on a phone", () => {
  test.use({ hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });

  // Catches an icon a tap cannot open, or an editor wider than the screen.
  test("a tap opens the editor", async ({ page }) => {
    const { groupsPage } = await setup(page, [
      group("0a000001", "G", [rule("0b000001", "a.example.com", "Meta: CDN")]),
    ]);
    await groupsPage.expandGroup(0);

    await icon(page).tap();
    await expect(editor(page).locator("input")).toHaveValue("Meta: CDN");
    const box = await editor(page).boundingBox();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(390);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
      390,
    );
  });

  // Catches a tap outside the editor dropping what was typed.
  test("a tap outside the editor keeps the typed comment", async ({ page }) => {
    const { groupsPage } = await setup(page, [
      group("0a000001", "G", [rule("0b000001", "a.example.com")]),
    ]);
    await groupsPage.expandGroup(0);

    await icon(page).tap();
    await expect(editor(page).locator("input")).toBeFocused();
    await page.keyboard.type("on the go");
    await page.locator(".group-header input.group-name").first().tap();
    await expect(icon(page)).toHaveAttribute("aria-label", "Comment: on the go");
    await expect(status(page)).toHaveAttribute("data-kind", "unsaved");
  });
});
