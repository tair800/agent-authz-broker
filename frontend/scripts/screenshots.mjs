/**
 * Retake every screenshot in `docs/screenshots/` from the running console.
 *
 * These exist because the README's four images went stale. The banner across the top of every
 * screen was rewritten, and `approvals.png` and `audit.png` kept the old wording for as long as
 * anyone was willing to retake them by hand — which was long enough for a reviewer to notice that
 * the repository's own screenshots disagreed with the repository.
 *
 * Full-page captures, so a table is never cut off above its totals row. `matrix.png` had been
 * cropped past exactly that.
 *
 *     npx playwright install chromium     # once
 *     npm run start                       # or `npm run dev`
 *     npm run screenshots
 *
 * Not part of `npm run build` and not run in CI: it needs a browser binary and a server, and a
 * build that silently rewrote committed images would be worse than one that leaves them alone.
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(here, "..", "..", "docs", "screenshots");
const base = process.env.CONSOLE_URL ?? "http://localhost:3000";

/** The width the committed images were taken at. Height is whatever the page turns out to be. */
const WIDTH = 1500;

const SHOTS = [
  { file: "matrix.png", path: "/" },
  { file: "chain.png", path: "/chain" },
  { file: "approvals.png", path: "/approvals" },
  { file: "audit.png", path: "/audit" },
];

const browser = await chromium.launch();
const page = await browser.newPage({
  viewport: { width: WIDTH, height: 1000 },
  deviceScaleFactor: 1,
  colorScheme: "dark",
});

await fs.mkdir(out, { recursive: true });
for (const shot of SHOTS) {
  const url = `${base}${shot.path}`;
  const response = await page.goto(url, { waitUntil: "networkidle" });
  if (!response || !response.ok()) {
    throw new Error(`${url} answered ${response ? response.status() : "nothing"}`);
  }
  // A screen that rendered its failure state is not a screenshot of this console working, and
  // committing one would be the same class of mistake as committing a stale one.
  const failed = await page.locator("[data-failure]").count();
  if (failed > 0) throw new Error(`${url} rendered a failure state`);

  const file = path.join(out, shot.file);
  await page.screenshot({ path: file, fullPage: true });
  const { width, height } = await page.evaluate(() => ({
    width: document.documentElement.scrollWidth,
    height: document.documentElement.scrollHeight,
  }));
  console.log(`wrote ${shot.file}  ${width}x${height}  <- ${url}`);
}

await browser.close();
