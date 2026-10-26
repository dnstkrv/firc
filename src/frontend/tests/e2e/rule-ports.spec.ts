import { expect, test, type Page } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";
import { signedIn } from "./pages/session";

type Rule = {
  id: string;
  type: string;
  rule: string;
  enable: boolean;
  proto?: string;
  ports?: string;
};

const group = (rules: Rule[]) => ({
  id: "0a000001",
  name: "G",
  interface: "wg0",
  enable: true,
  devices: { allow: [], deny: [] },
  resolve: { tunnel: true, server: "" },
  rules,
  live: true,
});

const subnet = (extra: Partial<Rule> = {}): Rule => ({
  id: "0b000001",
  type: "subnet",
  rule: "10.0.0.0/8",
  enable: true,
  ...extra,
});

async function setup(page: Page, rules: Rule[]) {
  const daemon = { groups: [group(rules)], puts: [] as any[] };
  await page.addInitScript(() => localStorage.setItem("locale", JSON.stringify({ value: "ru" })));
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
  await page.goto("/");
  await expect(page.locator(".group")).toHaveCount(1);
  await groupsPage.expandGroup(0);
  return { daemon, groupsPage };
}

const pill = (page: Page, ruleIndex = 0) =>
  page.locator(".group-wrapper").first().locator(".rule").nth(ruleIndex).locator(".rule-ports");
const editor = (page: Page) => page.locator(".rule-ports-editor");
const portsInput = (page: Page) => editor(page).getByRole("textbox", { name: "Порты" });
const clickOutside = (page: Page) =>
  expect(async () => {
    await page.mouse.click(5, 300);
    await expect(editor(page)).toBeHidden({ timeout: 500 });
  }).toPass();
const tokens = (page: Page) => editor(page).locator(".port-token");
const proto = (page: Page, name: string) => editor(page).getByRole("radio", { name, exact: true });

test.describe("A subnet rule's protocol and ports", () => {
  // Catches the pill not summing up the choice, a range shown with a hyphen, or the PUT carrying spaces or the en dash.
  test("TCP with two ports reads on the pill and saves in the stored form", async ({ page }) => {
    const { daemon, groupsPage } = await setup(page, [subnet()]);

    await expect(pill(page)).toHaveText("любой протокол");
    await expect(pill(page)).toHaveAttribute("aria-label", "любой протокол");
    await expect(pill(page)).toHaveAttribute("aria-haspopup", "dialog");
    await expect(pill(page)).toHaveAttribute("aria-invalid", "false");
    await pill(page).click();
    await expect(proto(page, "Любой")).toHaveAttribute("aria-checked", "true");
    await expect(portsInput(page)).toHaveCount(0);

    await proto(page, "TCP").click();
    await expect(pill(page)).toHaveText("TCP · все порты");
    await portsInput(page).fill("443");
    await portsInput(page).press("Enter");
    await portsInput(page).fill("8000-9000");
    await portsInput(page).press("Enter");

    await expect(tokens(page)).toHaveText(["443", "8000–9000"]);
    await expect(portsInput(page)).toHaveValue("");
    await expect(pill(page)).toHaveText("TCP · 443, 8000–9000");
    await expect(pill(page)).toHaveAttribute("aria-label", "TCP · 443, 8000–9000");

    await groupsPage.save();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = daemon.puts[0].groups[0].rules[0];
    expect(sent.proto).toBe("tcp");
    expect(sent.ports).toBe("443,8000-9000");
  });

  // Catches «Любой» leaving the ports behind (a 400 from the daemon), or TCP bringing them back.
  test("«Любой» drops the ports and TCP does not bring them back", async ({ page }) => {
    const { daemon, groupsPage } = await setup(page, [subnet({ proto: "tcp", ports: "443" })]);

    await expect(pill(page)).toHaveText("TCP · 443");
    await pill(page).click();
    await expect(tokens(page)).toHaveText(["443"]);

    await proto(page, "Любой").click();
    await expect(portsInput(page)).toHaveCount(0);
    await expect(editor(page).getByText("Порты", { exact: true })).toHaveCount(0);
    await expect(pill(page)).toHaveText("любой протокол");

    await proto(page, "TCP").click();
    await expect(tokens(page)).toHaveCount(0);
    await expect(pill(page)).toHaveText("TCP · все порты");
    await proto(page, "Любой").click();

    await groupsPage.save();
    await expect.poll(() => daemon.puts.length).toBe(1);
    const sent = daemon.puts[0].groups[0].rules[0];
    expect("proto" in sent).toBe(false);
    expect("ports" in sent).toBe(false);
  });

  // Catches a sixteenth slot dropped without a word, Backspace not taking the last token, or × taking the wrong one.
  test("a sixteenth slot is refused aloud; Backspace and × remove tokens", async ({ page }) => {
    const ports = Array.from({ length: 13 }, (_, i) => String(i + 1)).join(",") + ",100-200";
    await setup(page, [subnet({ proto: "udp", ports })]);

    await pill(page).click();
    await expect(tokens(page)).toHaveCount(14);
    const limit = editor(page).getByRole("status");
    await expect(limit).toHaveCount(0);

    await portsInput(page).fill("999");
    await portsInput(page).press("Enter");
    await expect(tokens(page)).toHaveCount(14);
    await expect(portsInput(page)).toHaveValue("999");
    await expect(limit).toHaveText("Больше 15 портов нельзя");
    await expect(pill(page)).not.toContainText("999");

    await portsInput(page).fill("");
    await portsInput(page).press("Backspace");
    await expect(tokens(page)).toHaveCount(13);
    await expect(tokens(page).last()).toHaveText("13");
    await expect(limit).toHaveCount(0);

    await editor(page).getByRole("button", { name: "Удалить 1", exact: true }).click();
    await expect(tokens(page)).toHaveCount(12);
    await expect(tokens(page).first()).toHaveText("2");
    await expect(pill(page)).toHaveText(
      `UDP · ${Array.from({ length: 12 }, (_, i) => i + 2).join(", ")}`,
    );
  });

  // Catches a trailing comma not cutting a token, or a pasted list kept as one token with its spaces.
  test("a comma cuts a token and a pasted list becomes several", async ({ page }) => {
    const { daemon, groupsPage } = await setup(page, [subnet({ proto: "tcp" })]);

    await pill(page).click();
    await portsInput(page).pressSequentially("1000-2000,");
    await expect(tokens(page)).toHaveText(["1000–2000"]);
    await expect(portsInput(page)).toHaveValue("");

    await portsInput(page).fill("443, 80 , 8000-9000");
    await portsInput(page).press("Enter");
    await expect(tokens(page)).toHaveText(["1000–2000", "443", "80", "8000–9000"]);

    await groupsPage.save();
    await expect.poll(() => daemon.puts.length).toBe(1);
    expect(daemon.puts[0].groups[0].rules[0].ports).toBe("1000-2000,443,80,8000-9000");
  });

  // Catches a bad token added anyway, or refused without a reason.
  test("a bad port is refused with the reason", async ({ page }) => {
    await setup(page, [subnet({ proto: "tcp" })]);

    await pill(page).click();
    const reason = editor(page).getByRole("status");
    for (const [typed, why] of [
      ["0", "Порт — от 1 до 65535"],
      ["70000", "Порт — от 1 до 65535"],
      ["20-10", "Диапазон пишется от меньшего к большему"],
      ["a", "Порт или диапазон вида 1000-2000"],
    ]) {
      await portsInput(page).fill(typed);
      await portsInput(page).press("Enter");
      await expect(reason).toHaveText(why);
      await expect(tokens(page)).toHaveCount(0);
      await expect(portsInput(page)).toHaveValue(typed);
    }
    await expect(pill(page)).toHaveText("TCP · все порты");
  });

  // Catches Esc leaving the popover open or focus lost, and a port typed before a click outside being lost.
  test("Esc closes onto the pill; a typed port is kept on a click outside", async ({ page }) => {
    const { daemon, groupsPage } = await setup(page, [subnet({ proto: "tcp" })]);

    await pill(page).click();
    await expect(editor(page)).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(editor(page)).toBeHidden();
    await expect(pill(page)).toBeFocused();

    await pill(page).click();
    await portsInput(page).fill("53");
    await groupsPage.save();
    await expect.poll(() => daemon.puts.length).toBe(1);
    expect(daemon.puts[0].groups[0].rules[0].ports).toBe("53");
    await expect(pill(page)).toHaveText("TCP · 53");
  });

  // Catches a bad port typed and left behind being dropped, so Save sends the rule wider than typed.
  test("a bad port left in the input holds Save until it is fixed", async ({ page }) => {
    const { daemon, groupsPage } = await setup(page, [subnet()]);
    const status = page.locator(".group .live-status").first();

    await pill(page).click();
    await proto(page, "TCP").click();
    await expect(portsInput(page)).not.toHaveAttribute("inputmode", "numeric");
    await portsInput(page).fill("0");
    await groupsPage.save();

    await expect(editor(page)).toBeHidden();
    await expect(pill(page)).toHaveText("TCP · 0");
    await expect(pill(page)).toHaveClass(/\binvalid\b/);
    await expect(pill(page)).toHaveAttribute("aria-invalid", "true");
    await expect(groupsPage.saveButton).toHaveClass(/fail/);
    await expect(status).toHaveAttribute("data-kind", "unsaved");

    await pill(page).click();
    await expect(tokens(page)).toHaveText(["0"]);
    await expect(tokens(page).first()).toHaveClass(/\binvalid\b/);
    await editor(page).getByRole("button", { name: "Удалить 0", exact: true }).click();
    await expect(portsInput(page)).toBeFocused();
    await portsInput(page).fill("53");
    await groupsPage.save();
    await expect.poll(() => daemon.puts.length).toBe(1);
    expect(daemon.puts[0].groups[0].rules[0].ports).toBe("53");
  });

  // Catches a sixteenth slot left in the input being dropped on a click outside.
  test("an over-limit port left in the input turns the pill red", async ({ page }) => {
    const ports = Array.from({ length: 15 }, (_, i) => String(i + 1)).join(",");
    const { groupsPage } = await setup(page, [subnet({ proto: "udp", ports })]);

    await pill(page).click();
    await portsInput(page).fill("999");
    await clickOutside(page);
    await expect(pill(page)).toContainText("15, 999");
    await expect(pill(page)).toHaveClass(/\binvalid\b/);
    await expect(groupsPage.saveButton).toHaveClass(/fail/);
  });

  // Catches Esc keeping the edits made since the popover opened, or a click outside throwing them away.
  test("Esc restores what the popover opened with; a click outside keeps the edits", async ({
    page,
  }) => {
    await setup(page, [subnet({ proto: "tcp", ports: "443" })]);
    const status = page.locator(".group .live-status").first();

    await pill(page).click();
    await portsInput(page).fill("80");
    await portsInput(page).press("Enter");
    await proto(page, "UDP").click();
    await portsInput(page).fill("53");
    await expect(pill(page)).toHaveText("UDP · 443, 80");
    await page.keyboard.press("Escape");
    await expect(editor(page)).toBeHidden();
    await expect(pill(page)).toHaveText("TCP · 443");
    await expect(status).toHaveAttribute("data-kind", "live");

    await pill(page).click();
    await portsInput(page).fill("80");
    await portsInput(page).press("Enter");
    await clickOutside(page);
    await expect(pill(page)).toHaveText("TCP · 443, 80");
    await expect(status).toHaveAttribute("data-kind", "unsaved");
  });

  // Catches arrow keys doing nothing in the protocol choice.
  test("arrow keys move the protocol choice", async ({ page }) => {
    await setup(page, [subnet()]);

    await pill(page).click();
    await proto(page, "Любой").focus();
    await page.keyboard.press("ArrowRight");
    await expect(proto(page, "TCP")).toBeFocused();
    await expect(proto(page, "TCP")).toHaveAttribute("aria-checked", "true");
    await expect(pill(page)).toHaveText("TCP · все порты");
  });

  // Catches a pill on a name rule, or a protocol on one shown as fine.
  test("a domain rule has no pill unless it wrongly carries a protocol", async ({ page }) => {
    await setup(page, [
      { id: "0b000001", type: "domain", rule: "a.example.com", enable: true },
      { id: "0b000002", type: "domain", rule: "b.example.com", enable: true, proto: "tcp" },
    ]);

    await expect(pill(page, 0)).toHaveCount(0);
    await expect(pill(page, 1)).toBeVisible();
    await expect(pill(page, 1)).toHaveClass(/\binvalid\b/);
    await expect(pill(page, 1)).toHaveText("TCP · все порты");
    await expect(pill(page, 1)).toHaveAttribute("aria-invalid", "true");

    await pill(page, 1).click();
    await proto(page, "Любой").click();
    await expect(pill(page, 1)).toHaveCount(0);
    const pattern = page
      .locator(".group-wrapper")
      .first()
      .locator(".rule")
      .nth(1)
      .locator(".pattern-input");
    await expect(pattern).toBeFocused();
  });
});

test.describe("The protocol and ports on a phone", () => {
  test.use({ hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });

  // Catches a popover wider than the screen, a pill cut short, or a pill that pushes the row into a horizontal scroll.
  test("the pill and the popover fit at 390 px", async ({ page }) => {
    await setup(page, [subnet({ proto: "tcp", ports: "443,8000-9000" })]);

    const summary = pill(page).locator(".rule-ports-summary");
    expect(await summary.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
    await pill(page).tap();
    await expect(editor(page)).toBeVisible();
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBe(0);
    for (const box of [await pill(page).boundingBox(), await editor(page).boundingBox()]) {
      expect(box).not.toBeNull();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width).toBeLessThanOrEqual(390);
    }
  });
});
