/* Real Chromium smoke coverage. Install Playwright only as a CI/developer tool. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { chromium } = require(process.env.ARTEMIS_PLAYWRIGHT_PATH || 'playwright');

(async () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'artemis-ui-'));
  const artifacts = process.env.ARTEMIS_UI_ARTIFACTS || path.join(temporary, 'screenshots');
  fs.mkdirSync(artifacts, { recursive: true });
  const child = spawn(process.env.ARTEMIS_PYTHON || 'python', ['-m', 'artemis_v3.workbench', '--port', '0',
    '--review-db', path.join(temporary, 'reviews.sqlite')], { stdio: ['ignore', 'pipe', 'pipe'] });
  let browser, page;
  try {
    const origin = await new Promise((resolve, reject) => {
      let output = '';
      const timer = setTimeout(() => reject(new Error('Workbench startup timed out')), 15000);
      child.on('error', reject);
      child.stdout.on('data', data => {
        output += data;
        const match = output.match(/http:\/\/127\.0\.0\.1:\d+/);
        if (match) { clearTimeout(timer); resolve(match[0]); }
      });
      child.stderr.on('data', data => process.stderr.write(data));
    });
    browser = await chromium.launch({ headless: true });
    page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.setDefaultTimeout(15000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
    await page.goto(origin);
    await page.locator('#demo').click();
    await page.locator('#case').waitFor({ state: 'visible' });
    assert.match(await page.locator('#metrics').textContent(), /1 \/ 10/);
    assert.match(await page.locator('#overview').textContent(), /模型尚未接入/);
    await page.screenshot({ path: path.join(artifacts, 'workbench-desktop.png'), fullPage: true });

    await page.locator('[data-tab="process"]').click();
    assert.equal(await page.locator('#process .process-node').count(), 2);
    await page.locator('#process button').first().click();
    assert.equal(await page.locator('#evidence-list .evidence-card').count(), 1);
    await page.locator('#search').fill('');
    await page.locator('#category').selectOption('signature');
    await page.locator('#evidence-list input[type="checkbox"]').first().check();
    await page.locator('[data-tab="timeline"]').click();
    assert.equal(await page.locator('#timeline .timeline-item').count(), 2);

    await page.locator('[data-tab="review"]').click();
    await page.locator('#reviewer').fill('UI synthetic analyst');
    await page.locator('#delta').fill('-1');
    await page.locator('#rationale').fill('Synthetic contextual proposal');
    await page.locator('#reason').fill('Synthetic browser workflow check');
    await page.locator('#decision').selectOption('defer');
    await page.locator('#submit-review').click();
    await page.waitForFunction(() => document.getElementById('review-result').textContent.includes('已保存'));
    assert.equal(await page.locator('#history-list .history-record').count(), 1);
    const downloadPromise = page.waitForEvent('download');
    await page.locator('#export-json').click();
    const exported = JSON.parse(fs.readFileSync(await (await downloadPromise).path(), 'utf8'));
    assert.equal(exported.rule_assessment.base_score, 1);
    assert.equal(exported.analyst_review.decision, 'defer');
    assert.equal(exported.analyst_review.analyst_score, null);

    // Import hostile text and confirm it stays text in the real browser DOM.
    const report = JSON.parse(fs.readFileSync('tests/fixtures/cape_synthetic.json', 'utf8'));
    report.behavior.processes[0].process_name = '<img src=x onerror="window.__artemis_xss=1">';
    await page.locator('#report-file').setInputFiles({ name: 'synthetic-hostile.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(report)) });
    await page.waitForFunction(() => !document.getElementById('analyze').disabled);
    await page.locator('#synthetic').check();
    await page.locator('#analyze').click();
    await page.locator('#case').waitFor({ state: 'visible' });
    await page.locator('[data-tab="process"]').click();
    assert.match(await page.locator('#process').textContent(), /<img/);
    assert.equal(await page.locator('#process img').count(), 0);
    assert.equal(await page.evaluate(() => window.__artemis_xss), undefined);

    await page.locator('[data-tab="overview"]').click();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: path.join(artifacts, 'workbench-mobile.png'), fullPage: true });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'Mobile document must not overflow horizontally');
    assert.deepEqual(errors, []);
    console.log('PASS: desktop/mobile demo, process links, timeline, citations, persisted review, export and hostile text');
  } finally {
    if (page && !page.isClosed()) await page.screenshot({ path: path.join(artifacts, 'workbench-final.png'), fullPage: true }).catch(() => {});
    if (browser) await browser.close();
    child.kill('SIGTERM');
    fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
