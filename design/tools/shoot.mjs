// Renders the mock-ups to PNG for review. Usage: node tools/shoot.mjs [playwrightDir]
// Playwright is resolved from the site-wt/shots node_modules by default (nothing is installed here).
import { createRequire } from 'node:module';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readFileSync, existsSync } from 'node:fs';
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const pwDir = process.argv[2] && process.argv[2] !== "-" ? process.argv[2] : join(root, '../../site-wt/shots');
const { chromium } = createRequire(join(pwDir, 'package.json'))('playwright');
const only = process.argv[3];
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1500, height: 1000 }, deviceScaleFactor: 2, reducedMotion: 'no-preference' });
async function shoot(file, sel, list, lang, theme, prefix) {
  for (const id of list) {
    if (only && !id.includes(only) && only !== file) continue;
    await page.goto(pathToFileURL(join(root, file)).href + `#s=${id}&l=${lang}&t=${theme}&shot=1`);
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(350);
    await page.locator(sel).screenshot({ path: join(root, 'review', `${prefix}-${id}-${lang}-${theme}.png`), animations: 'allow' });
  }
}
for (const [file, sel, prefix] of [['phone.html', '.device', 'phone'], ['pc.html', '.window', 'pc']]) {
  if (!existsSync(join(root, file)) || (only && only === 'icons')) continue;
  await page.goto(pathToFileURL(join(root, file)).href);
  const ids = await page.evaluate(() => window.SCREEN_IDS);
  await shoot(file, sel, ids, 'ar', 'light', prefix);
  await shoot(file, sel, ['home'], 'en', 'dark', prefix);
}
// icon sheet
const svg = f => readFileSync(join(root, f), 'utf8');
const cell = (f, s, bg) => `<div style="background:${bg};padding:12px;display:grid;place-items:center"><img src="data:image/svg+xml;base64,${Buffer.from(svg(f)).toString('base64')}" width="${s}" height="${s}"></div>`;
const files = ['icon.svg', 'icon-mono.svg', 'icon-alternatives/a-side-by-side.svg', 'icon-alternatives/b-arc.svg', 'icon-alternatives/c-photo-flight.svg'];
let html = '<body style="margin:0;font:14px system-ui;background:#fff"><div id=s style="display:inline-grid;grid-template-columns:auto repeat(9,auto);gap:4px;align-items:center;padding:12px">';
for (const f of files) { html += `<div style="padding:0 8px">${f}</div>`; for (const bg of ['#FBFDF8', '#202020']) for (const s of [192, 48, 32, 24]) html += cell(f, s, bg); html += `<div></div>`; }
html += '</div>';
await page.setContent(html); await page.waitForTimeout(200);
if (!only || only === 'icons') await page.locator('#s').screenshot({ path: join(root, 'review', 'icons.png') });
await browser.close();
console.log('done');
