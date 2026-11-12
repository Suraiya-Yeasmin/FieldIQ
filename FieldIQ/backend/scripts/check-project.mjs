import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.resolve(here, '../../frontend/FieldIQ.html');
const html = await readFile(htmlPath, 'utf8');
const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
const inlineScripts = scripts.filter(([, attrs]) => !/\bsrc\s*=/.test(attrs));
if (!inlineScripts.length) throw new Error('No inline application script was found in frontend/FieldIQ.html');
for (let i = 0; i < inlineScripts.length; i++) {
  new vm.Script(inlineScripts[i][2], { filename: `FieldIQ-inline-${i + 1}.js` });
}
console.log(`Frontend syntax check passed (${inlineScripts.length} inline script block(s)).`);
