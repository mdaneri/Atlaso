/** Capture the deployed proxy UI with session material confined to memory. */
import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';

let browser;
try {
  let input = '';
  for await (const chunk of process.stdin) {
    input += chunk;
    if (Buffer.byteLength(input) > 65536) throw new Error('input bound');
  }
  const envelope = JSON.parse(input);
  input = '';
  const base = new URL(envelope.base_url);
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash) throw new Error('invalid base');
  const output = path.resolve(envelope.output_dir);
  const stat = await fs.lstat(output);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('invalid output');
  const require = createRequire(path.join(envelope.packages_root, 'package.json'));
  const { chromium } = require('playwright');
  const sharp = require('sharp');
  browser = await chromium.launch({ executablePath: envelope.executable_path, headless: true });
  const context = await browser.newContext({ viewport: { width: 1600, height: 1000 }, ignoreHTTPSErrors: true });
  // Socket acceptance independently verifies the public listener certificate.
  // This management context changes no Windows trust store and saves no session state.
  await context.addCookies(envelope.cookies);
  envelope.cookies = [];
  const page = await context.newPage();
  await page.goto(base.origin + '/ui/management/traffic-publishing', { waitUntil: 'networkidle', timeout: 30000 });
  await page.locator('[data-tab-target="reverse-proxy-panel"]').click();
  await page.locator('#reverse-proxy-panel').waitFor({ state: 'visible' });
  await page.locator('[data-reverse-proxy-health-refresh]').click();
  await page.locator('#reverse-proxy-health-table .tabulator-row').first().waitFor({ state: 'visible', timeout: 15000 });
  async function capture(name) {
    const pixels = await page.screenshot({ fullPage: false });
    const destination = path.join(output, name + '.webp');
    const file = await fs.open(destination, 'wx');
    try { await file.writeFile(await sharp(pixels).webp({ quality: 86 }).toBuffer()); }
    finally { await file.close(); }
  }
  await capture('reverse-proxies');
  await page.setViewportSize({ width: 900, height: 1200 });
  await capture('reverse-proxies-responsive');
  await page.setViewportSize({ width: 1600, height: 1000 });
  await page.locator('[data-reverse-proxy-edit]').first().click();
  await page.locator('#reverse-proxy-dialog').waitFor({ state: 'visible' });
  await capture('reverse-proxy-wizard');
  await context.close();
  await browser.close();
  browser = undefined;
  process.stdout.write('Verified UI frames captured.\n');
} catch {
  // Never serialize browser errors, requests, cookie envelopes or response bodies.
  if (browser) await browser.close().catch(() => {});
  process.stderr.write('Reverse-proxy browser capture failed.\n');
  process.exitCode = 1;
}
