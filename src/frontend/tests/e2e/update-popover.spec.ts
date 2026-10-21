import { expect, test, type Page } from "@playwright/test";

import { signedIn } from "./pages/session";
import { upToDate } from "./pages/settings";

const latest = {
  ...upToDate.check.latest,
  version: "0.3.0",
  tag: "0.3.0",
  asset: { name: "firc_0.3.0-1_entware_mipsel-3.4_kn.ipk", size: 830000 },
};
const newer = { ...upToDate, check: { ...upToDate.check, ageS: 0, latest, newer: true } };
const checkFailed = { ...upToDate, check: { ...upToDate.check, error: "GitHub timed out" } };
const installFailed = { ...newer, state: "failed", error: "the digest does not match" };

async function shell(page: Page, status: unknown) {
  const calls = { checks: 0, installs: [] as unknown[] };
  await signedIn(page);
  await page.route("**/groups?with_rules=true", (r) => r.fulfill({ json: { groups: [] } }));
  await page.route("**/interfaces", (r) => r.fulfill({ json: { interfaces: [] } }));
  await page.route("**/system/update", (r) => r.fulfill({ json: status }));
  await page.route("**/system/update/check", (r) => {
    calls.checks++;
    return r.fulfill({ json: status });
  });
  await page.route("**/system/update/install", (r) => {
    calls.installs.push(r.request().postDataJSON());
    return r.fulfill({ status: 409, json: { error: "stop here" } });
  });
  await page.goto("/");
  return calls;
}

const openPopover = async (page: Page) => {
  await page.locator(".version-button").click();
  await expect(page.locator(".update-popover")).toBeVisible();
  return page.getByTestId("update-status");
};

// Catches an up-to-date build shown as anything else, a dot on it, or the notes link off the installed release.
test("an up-to-date build says so and links its own release", async ({ page }) => {
  await shell(page, upToDate);
  await expect(page.getByTestId("update-dot")).toHaveCount(0);
  const status = await openPopover(page);
  await expect(status).toContainText("Latest version");
  await expect(status).toContainText("checked 0 min ago");
  await expect(status).toBeDisabled();
  await expect(status).toHaveAttribute("data-state", "idle");
  await expect(page.getByRole("link", { name: "0.2.0 · What's new" })).toHaveAttribute(
    "href",
    "https://github.com/hoaxisr/firc/releases/tag/0.2.0",
  );
});

// Catches a newer release without a blue dot, without the install button, or an install that does not ask the same way Settings does.
test("a newer release is installed from the popover through the same request", async ({ page }) => {
  const calls = await shell(page, newer);
  await expect(page.getByTestId("update-dot")).toHaveAttribute("data-tone", "newer");
  const status = await openPopover(page);
  await expect(status).toHaveText(/Install 0\.3\.0/);
  await expect(page.getByRole("link", { name: "0.3.0 · What's new" })).toHaveAttribute(
    "href",
    "https://github.com/hoaxisr/firc/releases/tag/0.3.0",
  );
  await expect(status).toHaveAttribute("data-state", "action");
  await status.click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("Install 0.3.0?");
  await dialog.getByRole("button", { name: "Install" }).click();
  await expect.poll(() => calls.installs).toEqual([{ version: "0.3.0" }]);
});

// Catches Check in the popover not asking the daemon for a check.
test("Check in the popover runs a check", async ({ page }) => {
  const calls = await shell(page, upToDate);
  await openPopover(page);
  await page.getByTestId("update-check").click();
  await expect.poll(() => calls.checks).toBe(1);
});

// Catches a failed check shown as up to date, with no reason, or with a blue or no dot.
test("a failed check is named with its reason and a red dot", async ({ page }) => {
  await shell(page, checkFailed);
  await expect(page.getByTestId("update-dot")).toHaveAttribute("data-tone", "failed");
  const status = await openPopover(page);
  await expect(status).toContainText("Check failed");
  await expect(status).toContainText("GitHub timed out");
});

// Catches a failed install hidden behind the newer release it was for.
test("a failed install is named before the release it was for", async ({ page }) => {
  await shell(page, installFailed);
  await expect(page.getByTestId("update-dot")).toHaveAttribute("data-tone", "failed");
  const status = await openPopover(page);
  await expect(status).toContainText("The install failed");
  await expect(status).toContainText("the digest does not match");
});

// Catches the popover spilling past a phone's screen.
for (const width of [360, 390]) {
  test(`the popover fits a ${width} px phone`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await shell(page, newer);
    await openPopover(page);
    const box = await page.locator(".update-popover").boundingBox();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(width);
  });
}

// Catches Escape leaving the popover open, or focus lost instead of back on the version.
test("Escape closes the popover and gives focus back to the version", async ({ page }) => {
  await shell(page, upToDate);
  await openPopover(page);
  await page.keyboard.press("Escape");
  await expect(page.locator(".update-popover")).toHaveCount(0);
  await expect(page.locator(".version-button")).toBeFocused();
});

// Catches a download in progress drawn like the grey up-to-date button, clickable, or without its percentage.
test("a download in progress keeps the busy primary look with its percentage", async ({ page }) => {
  await shell(page, { ...newer, state: "downloading", progress: { bytes: 1, total: 4 } });
  const status = await openPopover(page);
  await expect(status).toHaveAttribute("data-state", "busy");
  await expect(status).toHaveClass(/primary/);
  await expect(status).toBeDisabled();
  await expect(status).toContainText("Downloading 0.3.0…");
  await expect(status.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "25");
});

// Catches a running check shown in the disabled grey style, or without any sign of work.
test("a check in progress shows as busy, not as up to date", async ({ page }) => {
  await signedIn(page);
  await page.route("**/groups?with_rules=true", (r) => r.fulfill({ json: { groups: [] } }));
  await page.route("**/interfaces", (r) => r.fulfill({ json: { interfaces: [] } }));
  await page.route("**/system/update", (r) => r.fulfill({ json: upToDate }));
  await page.route("**/system/update/check", async (r) => {
    await new Promise((done) => setTimeout(done, 1500));
    await r.fulfill({ json: upToDate });
  });
  await page.goto("/");
  const status = await openPopover(page);
  await page.getByTestId("update-check").click();
  await expect(status).toHaveAttribute("data-state", "busy");
  await expect(status).toHaveClass(/primary/);
  await expect(status.locator(".pulse")).toHaveCount(1);
  await expect(status).toHaveAttribute("data-state", "idle");
});

// Catches a development build's link naming a tag that does not exist instead of the releases list.
test("a development build links all releases", async ({ page }) => {
  await shell(page, {
    ...upToDate,
    installed: { ...upToDate.installed, version: "0.3.1~git20261016192753.07a8f2a" },
  });
  await openPopover(page);
  await expect(page.getByRole("link", { name: "All releases" })).toHaveAttribute(
    "href",
    "https://github.com/hoaxisr/firc/releases",
  );
});

const OPKG_SAID =
  "Collected errors:\n * pkg_hash_check_unresolved: cannot find dependency libcurl for firc\n";
const notLanded = (log: string) => ({
  ...upToDate,
  result: { version: "0.3.0", opkgExit: 255, finishedAt: 1791832000, log },
});

// Catches a failed install that cannot be opened, the popover left over the dialog, or a dialog that does not show what opkg printed.
test("a failed install opens what opkg printed", async ({ page }) => {
  await shell(page, notLanded(OPKG_SAID));
  await expect(page.getByTestId("update-dot")).toHaveAttribute("data-tone", "failed");
  const status = await openPopover(page);
  await expect(status).toContainText("0.3.0 not installed, opkg exit 255");
  await expect(status).not.toContainText("logread");
  await status.click();
  const dialog = page.getByRole("dialog", { name: "Why 0.3.0 did not install" });
  await expect(dialog).toBeVisible();
  await expect(page.locator(".update-popover")).toHaveCount(0);
  await expect(dialog).toContainText("opkg exit 255; firc 0.2.0 is still running.");
  expect(await dialog.getByTestId("update-log").textContent()).toBe(OPKG_SAID);
});

// Catches an empty log shown as a blank box instead of saying opkg printed nothing.
test("a failed install whose opkg printed nothing says so", async ({ page }) => {
  await shell(page, notLanded(""));
  const status = await openPopover(page);
  await status.click();
  const dialog = page.getByRole("dialog", { name: "Why 0.3.0 did not install" });
  await expect(dialog).toContainText("opkg printed nothing.");
  await expect(dialog.getByTestId("update-log")).toHaveCount(0);
});
