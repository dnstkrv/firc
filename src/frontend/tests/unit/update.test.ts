import assert from "node:assert";
import { describe, it } from "jsr:@std/testing@1.0.19/bdd";

import ru from "../../src/locales/ru.json" with { type: "json" };
import {
  CHECK_MAX_AGE_S,
  hasNewer,
  landed,
  needsCheck,
  reasonText,
  releaseLinkText,
  releaseUrl,
  resultCurrent,
  running,
  runningText,
  tagRelease,
  UPDATE_LIMIT_MS,
  updatePhase,
  updateStatus,
  type UpdateCheck,
  type UpdateRes,
} from "../../src/modules/settings/update.ts";

const t = (key: string) => key;

const check = (over: Partial<UpdateCheck> = {}): UpdateCheck => ({
  checkedAt: 1791831000,
  ageS: 0,
  latest: null,
  newer: false,
  installable: false,
  reason: null,
  error: null,
  ...over,
});

const res = (c: UpdateCheck | null): UpdateRes => ({
  installed: { version: "0.2.0", revision: 1, target: "mipsel-3.4_kn" },
  canInstall: true,
  reason: null,
  check: c,
  state: "idle",
  progress: null,
  error: null,
  result: null,
});

describe("needsCheck", () => {
  // Catches a page that never checks because the daemon has not checked since start.
  it("asks when the daemon holds no check", () => {
    assert.strictEqual(needsCheck(res(null)), true);
  });

  // Catches every open of the tab spending one of GitHub's 60 requests an hour.
  it("leaves a check younger than an hour alone", () => {
    assert.strictEqual(needsCheck(res(check({ ageS: 3599 }))), false);
  });

  // Catches > for >=, so an hour-old check is kept one more open.
  it("asks again once the check is an hour old", () => {
    assert.strictEqual(CHECK_MAX_AGE_S, 3600);
    assert.strictEqual(needsCheck(res(check({ ageS: 3600 }))), true);
  });

  // Catches staleness judged on checkedAt against the browser's clock instead of ageS.
  it("judges age by ageS, not by checkedAt", () => {
    assert.strictEqual(needsCheck(res(check({ ageS: 10, checkedAt: 1 }))), false);
    assert.strictEqual(
      needsCheck(res(check({ ageS: 7200, checkedAt: Math.floor(Date.now() / 1000) }))),
      true,
    );
  });

  // Catches a check fired before the daemon answered the status at all.
  it("asks nothing before the status arrived", () => {
    assert.strictEqual(needsCheck(null), false);
  });
});

describe("hasNewer", () => {
  // Catches a dot shown with no status, with no check, or for an up-to-date build.
  it("is true only for a check that found a newer release", () => {
    assert.strictEqual(hasNewer(null), false);
    assert.strictEqual(hasNewer(res(null)), false);
    assert.strictEqual(hasNewer(res(check({ newer: false }))), false);
    assert.strictEqual(hasNewer(res(check({ newer: true }))), true);
  });
});

describe("reasonText", () => {
  const REASONS = [
    "no-target",
    "unknown-version",
    "dev-build",
    "no-asset",
    "many-assets",
    "not-uploaded",
    "no-digest",
    "bad-size",
    "bad-url",
    "prerelease",
  ];

  // Catches a daemon reason shown as its raw key, or a text missing from ru.json.
  it("translates every reason the daemon sends", () => {
    for (const reason of REASONS) {
      const text = reasonText(reason, t);
      assert.notStrictEqual(text, reason, reason);
      assert.ok((ru as Record<string, string>)[text], `${reason}: ${text}`);
    }
  });

  // Catches two reasons sharing one text, so the operator cannot tell them apart.
  it("gives each reason its own text", () => {
    assert.strictEqual(new Set(REASONS.map((r) => reasonText(r, t))).size, REASONS.length);
  });

  // Catches an unknown reason shown as nothing, or null shown as a word.
  it("shows an unknown reason as it came and null as nothing", () => {
    assert.strictEqual(reasonText("from-the-future", t), "from-the-future");
    assert.strictEqual(reasonText(null, t), "");
  });
});

describe("updatePhase", () => {
  const target = { version: "0.3.0", revision: 1 };
  const at = (version: string, revision: number, state: UpdateRes["state"]): UpdateRes => ({
    ...res(null),
    installed: { version, revision, target: "mipsel-3.4_kn" },
    state,
  });

  // Catches a poll with no answer read as an outcome.
  it("is no-answer without an answer", () => {
    assert.strictEqual(updatePhase(target, null), "no-answer");
  });

  // Catches a daemon without the route, which is not the one that started, read as no answer.
  it("is back on a 404", () => {
    assert.strictEqual(updatePhase(target, null, 404), "back");
  });

  // Catches nginx's answer for a stopped daemon read as a failed install.
  it("is no-answer on a 502", () => {
    assert.strictEqual(updatePhase(target, null, 502), "no-answer");
  });

  // Catches a daemon running the target not taken as done.
  it("is back once the target runs", () => {
    assert.strictEqual(updatePhase(target, at("0.3.0", 1, "idle")), "back");
    assert.strictEqual(updatePhase(target, at("0.3.0", 1, "installing")), "back");
  });

  // Catches comparing the version only.
  it("is failed for the same version at another revision", () => {
    assert.strictEqual(
      updatePhase({ version: "0.3.0", revision: 2 }, at("0.3.0", 1, "idle")),
      "failed",
    );
  });

  // Catches the old daemon, still installing, read as an install that did not land.
  it("is old-daemon while the old daemon installs", () => {
    assert.strictEqual(updatePhase(target, at("0.2.0", 1, "installing")), "old-daemon");
  });

  // Catches an old daemon that answers idle waited on until the limit.
  it("is failed when the old version answers idle", () => {
    assert.strictEqual(updatePhase(target, at("0.2.0", 1, "idle")), "failed");
  });

  // Catches one dropped poll mid-download ending in "Not installed" while the download goes on.
  it("is old-daemon while the old daemon downloads or verifies", () => {
    assert.strictEqual(updatePhase(target, at("0.2.0", 1, "downloading")), "old-daemon");
    assert.strictEqual(updatePhase(target, at("0.2.0", 1, "verifying")), "old-daemon");
  });

  // Catches a failed download on the old daemon waited on until the limit.
  it("is failed when the old version answers failed", () => {
    assert.strictEqual(updatePhase(target, at("0.2.0", 1, "failed")), "failed");
  });

  // Catches a new daemon without its update checker waited out as never back.
  it("is back on the daemon's own 503", () => {
    const body = JSON.stringify({ error: "the update checker is not running" });
    assert.strictEqual(updatePhase(target, null, 503, body), "back");
  });

  // Catches an empty or proxy-made 503, from no daemon at all, read as one that answered.
  it("is no-answer on a 503 without the daemon's body", () => {
    assert.strictEqual(updatePhase(target, null, 503, ""), "no-answer");
    assert.strictEqual(updatePhase(target, null, 503, "<html>503</html>"), "no-answer");
    assert.strictEqual(updatePhase(target, null, 503), "no-answer");
  });

  // Catches a limit shorter than a slow mipsel install or the restart's own 120 s.
  it("waits five minutes", () => {
    assert.strictEqual(UPDATE_LIMIT_MS, 300_000);
  });
});

describe("tagRelease", () => {
  // Catches a -revN tag read as revision 1, or a v prefix refused.
  it("reads a tag as the daemon does", () => {
    assert.deepStrictEqual(tagRelease("0.3.0"), { version: "0.3.0", revision: 1 });
    assert.deepStrictEqual(tagRelease("v0.3.0"), { version: "0.3.0", revision: 1 });
    assert.deepStrictEqual(tagRelease("0.3.0-rev2"), { version: "0.3.0", revision: 2 });
    assert.deepStrictEqual(tagRelease("v10.20.30-rev12"), { version: "10.20.30", revision: 12 });
  });

  // Catches a tag the daemon refuses taken as some release.
  it("refuses what the daemon refuses", () => {
    for (const tag of ["0.3", "0.3.0-rev0", "0.3.0-beta", "x0.3.0", "0.3.0-rev", "", "0.3.0 "])
      assert.strictEqual(tagRelease(tag), null, tag);
  });
});

describe("landed", () => {
  const after = (version: string, revision: number, result: UpdateRes["result"]): UpdateRes => ({
    ...res(null),
    installed: { version, revision, target: "mipsel-3.4_kn" },
    result,
  });
  const r = (version: string, opkgExit = 0) => ({ version, opkgExit, finishedAt: 1791832000 });

  // Catches a tag compared with the bare installed version, so a -revN install reads as failed.
  it("matches a -rev tag on version and revision", () => {
    assert.strictEqual(landed(after("0.3.0", 2, r("0.3.0-rev2"))), true);
    assert.strictEqual(landed(after("0.3.0", 1, r("0.3.0-rev2"))), false);
  });

  // Catches a v-prefixed tag never matching the installed version.
  it("matches a v tag", () => {
    assert.strictEqual(landed(after("0.3.0", 1, r("v0.3.0"))), true);
  });

  // Catches opkg's failure shown as landed, or no result shown as landed.
  it("needs opkg's exit 0 and a result", () => {
    assert.strictEqual(landed(after("0.3.0", 1, r("0.3.0", 255))), false);
    assert.strictEqual(landed(after("0.3.0", 1, null)), false);
  });
});

describe("resultCurrent", () => {
  const at = (version: string, revision: number, tag: string): UpdateRes => ({
    ...res(null),
    installed: { version, revision, target: "mipsel-3.4_kn" },
    result: { version: tag, opkgExit: 255, finishedAt: 1791832000 },
  });

  // Catches a failed install of an older release still shown after a newer one was installed by hand.
  it("hides a result older than the installed release", () => {
    assert.strictEqual(resultCurrent(at("0.3.0", 1, "0.2.0")), false);
    assert.strictEqual(resultCurrent(at("0.3.0", 2, "0.3.0")), false);
    assert.strictEqual(resultCurrent(at("0.10.0", 1, "0.9.9")), false);
  });

  // Catches a failed upgrade, or this release's own result, hidden.
  it("keeps a result for the installed release or a newer one", () => {
    assert.strictEqual(resultCurrent(at("0.3.0", 1, "0.4.0")), true);
    assert.strictEqual(resultCurrent(at("0.3.0", 1, "0.3.0-rev2")), true);
    assert.strictEqual(resultCurrent(at("0.3.0", 1, "v0.3.0")), true);
  });

  // Catches a dev build or an unreadable tag hiding what opkg said.
  it("keeps a result it cannot compare", () => {
    assert.strictEqual(resultCurrent(at("0.2.1~git20261013152446.24cf8cc", 1, "0.2.0")), true);
    assert.strictEqual(resultCurrent(at("0.3.0", 1, "latest")), true);
  });
});

describe("running", () => {
  // Catches Install or Restart left live during a phase of an install, or held after one.
  it("is true for the three install phases only", () => {
    for (const state of ["downloading", "verifying", "installing"] as const)
      assert.strictEqual(running({ ...res(null), state }), true, state);
    for (const state of ["idle", "checking", "failed"] as const)
      assert.strictEqual(running({ ...res(null), state }), false, state);
    assert.strictEqual(running(null), false);
  });
});

const LATEST = {
  version: "0.3.0",
  revision: 1,
  tag: "0.3.0",
  publishedAt: "2026-10-15T10:00:00Z",
  notes: "",
  asset: { name: "firc.ipk", size: 1 },
};
const idle = { checking: false, checkError: "" };

describe("updateStatus", () => {
  // Catches a fresh check read as anything but up to date, or its age not in whole minutes.
  it("is up to date after a check that found nothing newer", () => {
    assert.deepStrictEqual(updateStatus(res(check({ ageS: 299 })), idle), {
      kind: "up-to-date",
      minutes: 4,
    });
  });

  // Catches a newer release not offered, offered when the router cannot install it, or the wrong version named.
  it("offers a newer release only when it can be installed", () => {
    const newer = check({ latest: LATEST, newer: true, installable: true });
    assert.deepStrictEqual(updateStatus(res(newer), idle), {
      kind: "newer",
      version: "0.3.0",
      offered: true,
    });
    assert.deepStrictEqual(updateStatus({ ...res(newer), canInstall: false }, idle), {
      kind: "newer",
      version: "0.3.0",
      offered: false,
    });
  });

  // Catches a failed check shown as up to date, or the page's own check error ranked below the daemon's.
  it("names a failed check, the page's error first", () => {
    assert.deepStrictEqual(updateStatus(res(check({ error: "timeout" })), idle), {
      kind: "check-failed",
      error: "timeout",
    });
    assert.deepStrictEqual(
      updateStatus(res(check({ error: "timeout" })), { checking: false, checkError: "429" }),
      { kind: "check-failed", error: "429" },
    );
  });

  // Catches a failed install hidden behind a newer release, or an opkg failure on the last run not reported.
  it("names a failed install before anything else that is settled", () => {
    const newer = check({ latest: LATEST, newer: true, installable: true });
    assert.deepStrictEqual(
      updateStatus({ ...res(newer), state: "failed", error: "bad digest" }, idle),
      {
        kind: "install-failed",
        error: "bad digest",
      },
    );
    assert.deepStrictEqual(
      updateStatus(
        { ...res(check()), result: { version: "0.3.0", opkgExit: 255, finishedAt: 1 } },
        idle,
      ),
      { kind: "not-installed", version: "0.3.0", code: 255 },
    );
  });

  // Catches a running install or a check in flight shown as a settled state, or the download percentage wrong.
  it("shows work in progress over everything", () => {
    const newer = check({ latest: LATEST, newer: true, installable: true });
    assert.deepStrictEqual(
      updateStatus({ ...res(newer), state: "downloading", progress: { bytes: 1, total: 3 } }, idle),
      { kind: "running", state: "downloading", version: "0.3.0", percent: 33 },
    );
    assert.deepStrictEqual(updateStatus({ ...res(newer), state: "installing" }, idle), {
      kind: "running",
      state: "installing",
      version: "0.3.0",
      percent: null,
    });
    assert.deepStrictEqual(
      updateStatus(res(check({ error: "x" })), { checking: true, checkError: "" }),
      {
        kind: "checking",
      },
    );
  });

  // Catches a router that never checked shown as up to date.
  it("says nothing was checked yet", () => {
    assert.deepStrictEqual(updateStatus(res(null), idle), { kind: "unchecked" });
  });
});

describe("releaseLinkText", () => {
  // Catches the link naming the installed version while it opens the newer release, or a build named as if it were a release.
  it("names the release the link opens, or all releases for a build", () => {
    assert.strictEqual(releaseLinkText(res(check()), t), "0.2.0 · What's new");
    assert.strictEqual(
      releaseLinkText(res(check({ latest: LATEST, newer: true })), t),
      "0.3.0 · What's new",
    );
    assert.strictEqual(
      releaseLinkText(res(check({ latest: LATEST, newer: false })), t),
      "0.2.0 · What's new",
    );
    const build = {
      ...res(check()),
      installed: { version: "0.3.1~git20261016192753.07a8f2a", revision: 1, target: "" },
    };
    assert.strictEqual(releaseLinkText(build, t), "All releases");
    assert.strictEqual(releaseUrl(build), "https://github.com/hoaxisr/firc/releases");
    const buildWithNewer = { ...build, check: check({ latest: LATEST, newer: true }) };
    assert.strictEqual(releaseLinkText(buildWithNewer, t), "0.3.0 · What's new");
    assert.strictEqual(
      releaseUrl(buildWithNewer),
      "https://github.com/hoaxisr/firc/releases/tag/0.3.0",
    );
  });
});

describe("runningText", () => {
  // Catches a phase named wrongly, or the download without the version it fetches.
  it("names each phase of an install", () => {
    assert.strictEqual(runningText("downloading", "0.3.0", t), "Downloading 0.3.0…");
    assert.strictEqual(runningText("verifying", "0.3.0", t), "Checking the package…");
    assert.strictEqual(runningText("installing", "0.3.0", t), "Installing…");
  });
});

describe("releaseUrl", () => {
  // Catches a later revision linked to the first one's tag, or a development build linked to a tag that does not exist.
  it("links the installed revision's tag, and the releases list for a development build", () => {
    assert.strictEqual(
      releaseUrl({ ...res(check()), installed: { version: "0.2.0", revision: 3, target: "" } }),
      "https://github.com/hoaxisr/firc/releases/tag/0.2.0-rev3",
    );
    assert.strictEqual(
      releaseUrl({
        ...res(check()),
        installed: { version: "0.0.0~git1.abc", revision: 1, target: "" },
      }),
      "https://github.com/hoaxisr/firc/releases",
    );
  });

  // Catches the notes link pointing at the installed release while a newer one is offered, or at the wrong repository.
  it("links the newer release when there is one, else the installed one", () => {
    assert.strictEqual(
      releaseUrl(res(check())),
      "https://github.com/hoaxisr/firc/releases/tag/0.2.0",
    );
    assert.strictEqual(
      releaseUrl(res(check({ latest: LATEST, newer: true }))),
      "https://github.com/hoaxisr/firc/releases/tag/0.3.0",
    );
  });
});
