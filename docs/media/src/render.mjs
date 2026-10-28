// Render every HTML page in a directory to a PNG at 2x with headless
// Chromium (Playwright). Usage: node render.mjs HTML_DIR OUT_DIR
import { chromium } from 'playwright';
import { readdirSync } from 'node:fs';
import { join, resolve, basename } from 'node:path';

const [, , htmlDir, outDir] = process.argv;
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1270, height: 760 }, deviceScaleFactor: 2 });
for (const f of readdirSync(htmlDir).filter((f) => f.endsWith('.html')).sort()) {
  await page.goto('file://' + resolve(htmlDir, f));
  await page.evaluate(async () => {
    await document.fonts.ready;
    if (window.fit) window.fit();
  });
  const out = join(outDir, basename(f, '.html') + '.png');
  await page.screenshot({ path: out });
  console.log(out);
}
await browser.close();
