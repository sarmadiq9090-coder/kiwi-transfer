// Renders the mock-ups to PNG for review. Usage: node tools/shoot.mjs [playwrightDir]
// Playwright is resolved from the site-wt/shots node_modules by default (nothing is installed here).
import { createRequire } from 'node:module';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const pwDir = process.argv[2] && process.argv[2] !== "-" ? process.argv[2] : join(root, '../../../site-wt/shots');
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
// the mono icon is a template (Android themed icon / Windows tray): shown in its own colour on light and in white on dark
const cell = (f, s, bg) => `<div style="background:${bg};padding:12px;display:grid;place-items:center"><img src="data:image/svg+xml;base64,${Buffer.from(svg(f)).toString('base64')}" width="${s}" height="${s}" style="${f.includes('mono') && bg !== '#FBFDF8' ? 'filter:brightness(0) invert(1)' : ''}"></div>`;
const files = ['icon.svg', 'icon-mono.svg', 'icon-alternatives/b-arc.svg', 'icon-alternatives/c-photo-flight.svg', 'icon-alternatives/d-phone-in-front.svg'];
let html = '<body style="margin:0;font:14px system-ui;background:#fff"><div id=s style="display:inline-grid;grid-template-columns:auto repeat(9,auto);gap:4px;align-items:center;padding:12px">';
for (const f of files) { html += `<div style="padding:0 8px">${f}</div>`; for (const bg of ['#FBFDF8', '#202020']) for (const s of [192, 48, 32, 24]) html += cell(f, s, bg); html += `<div></div>`; }
html += '</div>';
await page.setContent(html); await page.waitForTimeout(200);
if (!only || only === 'icons') await page.locator('#s').screenshot({ path: join(root, 'review', 'contact-icons.png') });
// contact sheets: every Arabic-light screen plus the English-dark home, one PNG per device
for (const [prefix, w, cols] of [['phone', 220, 8], ['pc', 520, 4]]) {
  if (only && only !== 'contact' && !(only === prefix + '.html')) continue;
  const files = readdirSync(join(root, 'review')).filter(f => f.startsWith(prefix + '-') && f.endsWith('.png'));
  const order = (await (async () => { await page.goto(pathToFileURL(join(root, prefix + '.html')).href); return page.evaluate(() => window.SCREEN_IDS); })());
  const list = order.map(id => `${prefix}-${id}-ar-light.png`).filter(f => files.includes(f)).concat(files.filter(f => f.includes('-en-dark')));
  let h = `<body style="margin:0;background:#EEF2EA;font:600 13px system-ui;color:#4A5A42"><div id=c style="display:inline-grid;grid-template-columns:repeat(${cols},${w}px);gap:28px 20px;padding:28px">`;
  for (const f of list) h += `<figure style="margin:0"><img src="data:image/png;base64,${readFileSync(join(root, 'review', f)).toString('base64')}" style="width:${w}px;display:block"><figcaption style="margin-top:6px">${f.replace(prefix + '-', '').replace('.png', '')}</figcaption></figure>`;
  await page.setViewportSize({ width: cols * (w + 20) + 80, height: 1000 });
  await page.setContent(h + '</div>'); await page.waitForTimeout(300);
  await page.locator('#c').screenshot({ path: join(root, 'review', `contact-${prefix}.png`), scale: 'css' });
  await page.setViewportSize({ width: 1500, height: 1000 });
}
// contact-new: only the screens marked new or changed (nw) since the owner approved 1.0, phone first, then PC
if (!only || only === 'contact' || only === 'new') {
  let h = '<body style="margin:0;background:#EEF2EA;font:600 13px system-ui;color:#4A5A42"><div id=c style="width:2260px;padding:28px">';
  for (const [prefix, w, cols, title] of [['phone', 220, 9, 'Phone: new or changed'], ['pc', 540, 4, 'PC: new or changed']]) {
    await page.goto(pathToFileURL(join(root, prefix + '.html')).href);
    const ids = await page.evaluate(() => window.NEW_IDS || []);
    h += `<h2 style="font:700 22px system-ui;color:#14200F;margin:8px 0 16px">${title} (${ids.length})</h2><div style="display:grid;grid-template-columns:repeat(${cols},${w}px);gap:24px 20px;margin-bottom:36px">`;
    for (const id of ids) { const f = `${prefix}-${id}-ar-light.png`; if (!existsSync(join(root, 'review', f))) continue;
      h += `<figure style="margin:0"><img src="data:image/png;base64,${readFileSync(join(root, 'review', f)).toString('base64')}" style="width:${w}px;display:block"><figcaption style="margin-top:6px">${id}</figcaption></figure>`; }
    h += '</div>';
  }
  await page.setViewportSize({ width: 2320, height: 1000 });
  await page.setContent(h + '</div>'); await page.waitForTimeout(300);
  await page.locator('#c').screenshot({ path: join(root, 'review', 'contact-new.png'), scale: 'css' });
}
await browser.close();
console.log('done');
