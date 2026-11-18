// Inlines IBM Plex Sans Arabic (OFL-1.1, see ../licenses) into the mock-ups as base64 @font-face rules,
// between the /*FONTS-BEGIN*/ and /*FONTS-END*/ markers. Idempotent. Usage: node embed-fonts.mjs <fontsDir>
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
const fontsDir = process.argv[2] || join(here, '../../../sarmadiq9090-coder.github.io/fonts');
const AR = 'U+0600-06FF, U+0750-077F, U+0870-088E, U+0890-0891, U+0897-08E1, U+08E3-08FF, U+200C-200E, U+2010-2011, U+204F, U+2E41, U+FB50-FDFF, U+FE70-FE74, U+FE76-FEFC';
const LA = 'U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD';
let css = '';
for (const [sub, range] of [['arabic', AR], ['latin', LA]]) for (const w of [400, 700]) {
  const b64 = readFileSync(join(fontsDir, `plex-arabic-${sub}-${w}.woff2`)).toString('base64');
  css += `@font-face{font-family:"Plex Arabic";font-weight:${w};font-display:block;src:url(data:font/woff2;base64,${b64}) format("woff2");unicode-range:${range}}\n`;
}
for (const f of ['phone.html', 'pc.html']) {
  const p = join(here, '..', f);
  if (!existsSync(p)) continue;
  const s = readFileSync(p, 'utf8');
  const out = s.replace(/\/\*FONTS-BEGIN\*\/[\s\S]*?\/\*FONTS-END\*\//, `/*FONTS-BEGIN*/\n${css}/*FONTS-END*/`);
  writeFileSync(p, out);
  console.log(f, s === out ? 'unchanged' : 'fonts embedded', (out.length / 1024).toFixed(0) + ' KB');
}
