import { expect, test, type Page } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

const DUPLICATE_PATTERN = "shared.example.com";

function buildLargeGroupRules() {
  return Array.from({ length: 60 }, (_, i) => ({
    id: `900000${i.toString().padStart(2, "0")}`,
    name: `Large Rule ${i}`,
    rule: i === 0 || i === 55 ? DUPLICATE_PATTERN : `unique-${i}.example.com`,
    type: "namespace",
    enable: true,
  }));
}

async function mockBaseRoutes(page: Page) {
  await signedIn(page);

  await page.route("**/interfaces", async (route) => {
    await route.fulfill({ json: { interfaces: [] } });
  });
}

test.describe("Duplicate Indicators", () => {
  let groupsPage: GroupsPage;

  test.beforeEach(async ({ page }) => {
    groupsPage = new GroupsPage(page);

    await mockBaseRoutes(page);

    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "g-large",
              name: "Large Group",
              devices: { allow: [], deny: [] },
              rules: buildLargeGroupRules(),
              enable: true,
              interface: "",
            },
            {
              id: "g-second",
              name: "Second Group",
              devices: { allow: [], deny: [] },
              rules: [
                {
                  id: "81000001",
                  name: "Second Duplicate",
                  rule: DUPLICATE_PATTERN,
                  type: "namespace",
                  enable: true,
                },
                {
                  id: "81000002",
                  name: "Second Unique",
                  rule: "another-unique.example.com",
                  type: "namespace",
                  enable: true,
                },
              ],
              enable: true,
              interface: "",
            },
            {
              id: "g-clean",
              name: "Clean Group",
              devices: { allow: [], deny: [] },
              rules: [
                {
                  id: "82000001",
                  name: "Clean Rule",
                  rule: "clean-only.example.com",
                  type: "namespace",
                  enable: true,
                },
              ],
              enable: true,
              interface: "",
            },
          ],
        },
      });
    });

    await groupsPage.goto();
  });

  test("should show duplicate markers across groups and paginated rules", async ({ page }) => {
    const groupHeaders = page.locator(".group-header");
    await expect(groupHeaders).toHaveCount(3);

    await expect(groupHeaders.nth(0).locator(".group-duplicate-indicator")).toBeVisible();
    await expect(groupHeaders.nth(1).locator(".group-duplicate-indicator")).toBeVisible();
    await expect(groupHeaders.nth(2).locator(".group-duplicate-indicator")).toHaveCount(0);

    await groupHeaders.nth(0).locator("[data-collapsible-trigger]").click();
    const largeGroup = page.locator(".group-wrapper").nth(0);
    await expect(largeGroup.locator(".rule")).toHaveCount(50);

    await expect(
      largeGroup.locator('.rule[data-group-index="0"][data-index="0"] .duplicate-indicator'),
    ).toHaveCount(0);
    await expect(
      largeGroup.locator('.rule[data-group-index="0"][data-index="1"] .duplicate-indicator'),
    ).toHaveCount(0);

    await largeGroup.getByTitle("Next Page").click();
    await expect(largeGroup.locator(".rule")).toHaveCount(10);
    const repeat = largeGroup.locator(
      '.rule[data-group-index="0"][data-index="55"] .duplicate-indicator',
    );
    await expect(repeat).toBeVisible();
    await expect(repeat).toHaveAttribute("data-overlap", "shadowed");

    await groupHeaders.nth(1).locator("[data-collapsible-trigger]").click();
    const secondGroup = page.locator(".group-wrapper").nth(1);
    const second = secondGroup.locator(
      '.rule[data-group-index="1"][data-index="0"] .duplicate-indicator',
    );
    await expect(second).toBeVisible();
    await expect(second).toHaveAttribute("data-overlap", "shadowed");
  });

  test("should render duplicate conflict menu and focus selected conflict", async ({ page }) => {
    const secondGroupHeader = page.locator(".group-header").nth(1);
    await secondGroupHeader.locator(".group-duplicate-indicator").click();

    const duplicateMenu = page.locator(".group-duplicate-menu-list");
    await expect(duplicateMenu).toBeVisible();

    const conflictButtons = duplicateMenu.locator(".duplicate-conflict-button");
    await expect(conflictButtons).toHaveCount(2);
    await expect(conflictButtons.filter({ hasText: "Large Group" })).toHaveCount(1);

    await conflictButtons.filter({ hasText: "Large Group" }).click();

    const focusedRule = page.locator('.rule[data-group-uuid="g-large"][data-uuid="90000000"]');
    await expect(focusedRule).toBeVisible();
    await expect(focusedRule).toHaveAttribute("data-duplicate-highlighted", "true");
  });
});

test.describe("Duplicate Indicators - split", () => {
  test.beforeEach(async ({ page }) => {
    await mockBaseRoutes(page);
    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "g-headset",
              name: "Headset",
              devices: { allow: ["192.168.1.5"], deny: [] },
              rules: [{ id: "93000001", rule: "meta.com", type: "namespace", enable: true }],
              enable: true,
              interface: "",
            },
            {
              id: "g-all",
              name: "Everyone",
              devices: { allow: [], deny: [] },
              rules: [{ id: "94000001", rule: "meta.com", type: "namespace", enable: true }],
              enable: true,
              interface: "",
            },
          ],
        },
      });
    });
    await new GroupsPage(page).goto();
  });

  test("a scoped upper group marks the lower copy as split, grey", async ({ page }) => {
    const groupHeaders = page.locator(".group-header");
    await expect(groupHeaders.nth(0).locator(".group-duplicate-indicator")).toHaveCount(0);
    await expect(groupHeaders.nth(1).locator(".group-duplicate-indicator")).toHaveAttribute(
      "data-overlap",
      "split",
    );
    await groupHeaders.nth(1).locator("[data-collapsible-trigger]").click();
    await expect(
      page.locator('.rule[data-group-uuid="g-all"][data-uuid="94000001"] .duplicate-indicator'),
    ).toHaveAttribute("data-overlap", "split");
  });
});

test.describe("Duplicate Indicators - empty patterns", () => {
  let groupsPage: GroupsPage;

  test.beforeEach(async ({ page }) => {
    groupsPage = new GroupsPage(page);

    await mockBaseRoutes(page);

    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "g-empty-a",
              name: "Empty Group A",
              rules: [
                {
                  id: "91000001",
                  name: "Empty Rule A",
                  rule: "",
                  type: "namespace",
                  enable: true,
                },
                {
                  id: "91000002",
                  name: "Whitespace Rule A",
                  rule: "   ",
                  type: "namespace",
                  enable: true,
                },
              ],
              enable: true,
              interface: "",
            },
            {
              id: "g-empty-b",
              name: "Empty Group B",
              rules: [
                {
                  id: "92000001",
                  name: "Empty Rule B",
                  rule: "",
                  type: "namespace",
                  enable: true,
                },
                {
                  id: "92000002",
                  name: "Whitespace Rule B",
                  rule: "   ",
                  type: "namespace",
                  enable: true,
                },
              ],
              enable: true,
              interface: "",
            },
          ],
        },
      });
    });

    await groupsPage.goto();
  });

  test("should ignore empty and whitespace-only patterns in duplicate detection", async ({
    page,
  }) => {
    const groupHeaders = page.locator(".group-header");
    await expect(groupHeaders).toHaveCount(2);

    await expect(groupHeaders.nth(0).locator(".group-duplicate-indicator")).toHaveCount(0);
    await expect(groupHeaders.nth(1).locator(".group-duplicate-indicator")).toHaveCount(0);

    await groupHeaders.nth(0).locator("[data-collapsible-trigger]").click();
    await groupHeaders.nth(1).locator("[data-collapsible-trigger]").click();

    await expect(page.locator(".duplicate-indicator")).toHaveCount(0);
  });
});

test.describe("Duplicate Indicators - recompute on change", () => {
  const unscoped = (id: string, name: string, ruleId: string, allow: string[] = []) => ({
    id,
    name,
    devices: { allow, deny: [] },
    rules: [{ id: ruleId, rule: "meta.com", type: "namespace", enable: true }],
    enable: true,
    interface: "eth0",
  });

  async function stubGroups(page: Page, groups: unknown[]) {
    await mockBaseRoutes(page);
    await page.route("**/groups?with_rules=true", (route) => route.fulfill({ json: { groups } }));
    await page.route("**/system/hosts", (route) =>
      route.fulfill({
        json: {
          hosts: [
            {
              mac: "aa:00:00:00:00:03",
              name: "Phone",
              ip: "192.168.1.7",
              ip6: [],
              active: true,
              registered: true,
              policy: "",
            },
          ],
        },
      }),
    );
    await page.route("**/system/policies", (route) => route.fulfill({ json: { policies: [] } }));
    await new GroupsPage(page).goto();
  }

  // Catches the group switch not recomputing the marks.
  test("disabling the upper group clears the mark on the lower copy", async ({ page }) => {
    await stubGroups(page, [unscoped("g1", "One", "95000001"), unscoped("g2", "Two", "96000001")]);
    const headers = page.locator(".group-header");
    await expect(headers.nth(1).locator(".group-duplicate-indicator")).toBeVisible();
    await headers.nth(0).locator(".enable-group").click();
    await expect(headers.nth(1).locator(".group-duplicate-indicator")).toHaveCount(0);
  });

  // Catches the devices dialog closing without recomputing the marks.
  test("widening the lower selector flips shadowed to split", async ({ page }) => {
    await stubGroups(page, [
      unscoped("g1", "One", "95000001", ["192.168.1.5"]),
      unscoped("g2", "Two", "96000001", ["192.168.1.5"]),
    ]);
    const header = page.locator(".group-header").nth(1);
    await expect(header.locator(".group-duplicate-indicator")).toHaveAttribute(
      "data-overlap",
      "shadowed",
    );
    await header.locator("button", { has: page.locator(".devices-icon") }).click();
    await page.locator('li.host[data-mac="aa:00:00:00:00:03"] [role=switch]').click();
    await page.locator(".modal form button[type=submit]").click();
    await expect(header.locator(".group-duplicate-indicator")).toHaveAttribute(
      "data-overlap",
      "split",
    );
  });
});
