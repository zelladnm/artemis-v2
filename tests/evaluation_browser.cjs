/* Offline evaluation -> saved human judgments -> exact-run ratings, in Chromium. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');
const { chromium } = require(process.env.ARTEMIS_PLAYWRIGHT_PATH || 'playwright');

async function origin(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Startup timed out')), 15000);
    let output = '';
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); reject(new Error('Workbench exited: ' + code)); });
    child.stderr.on('data', data => process.stderr.write(data));
    child.stdout.on('data', data => {
      output += data;
      const match = output.match(/http:\/\/127\.0\.0\.1:\d+/);
      if (match) { clearTimeout(timer); resolve(match[0]); }
    });
  });
}
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Shutdown timed out')), 5000);
    child.once('exit', () => { clearTimeout(timer); resolve(); }); child.kill('SIGTERM');
  });
}

(async () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'artemis-eval-ui-'));
  const artifacts = process.env.ARTEMIS_UI_ARTIFACTS || path.join(temporary, 'artifacts');
  fs.mkdirSync(artifacts, { recursive: true });
  const python = process.env.ARTEMIS_PYTHON || 'python';
  const suite = 'tests/fixtures/semantic_eval/historical_suite.json';
  const replay = JSON.parse(fs.readFileSync('tests/fixtures/semantic_eval/historical_replay.json'));
  replay.outputs.single_source_control.source_observations[0].evidence_refs = ['invented'];
  const replayFile = path.join(temporary, 'replay.json'); fs.writeFileSync(replayFile, JSON.stringify(replay));
  const runDir = path.join(temporary, 'run'), runPath = path.join(runDir, 'run.json');
  // A rejected model contract stays in the run denominator and in the workbench list.
  try {
    execFileSync(python, ['-m', 'artemis_v3.evaluation', 'run', '--suite', suite, '--replay', replayFile, '--output-dir', runDir]);
    assert.fail('One synthetic output must be rejected');
  } catch (error) { assert.equal(error.status, 1); }
  const recorded = JSON.parse(fs.readFileSync(runPath)); assert.equal(recorded.summary.failed, 1);
  let child = spawn(python, ['-m', 'artemis_v3.workbench', '--port', '0', '--review-db', path.join(temporary, 'reviews.sqlite'),
    '--evaluation-suite', suite, '--evaluation-run', runPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  let browser, page;
  try {
    const url = await origin(child);
    browser = await chromium.launch({ headless: true });
    page = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); page.setDefaultTimeout(15000);
    const errors = [], unexpected = [], calls = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => {
      const request = route.request(); calls.push(new URL(request.url()).pathname);
      if (new URL(request.url()).origin === url) return route.continue();
      unexpected.push(request.url()); return route.abort();
    });
    await page.goto(url); await page.locator('#evaluation-panel').waitFor({ state: 'visible' });
    assert.match(await page.locator('#evaluation-info').textContent(), /合成回放/);
    assert.equal(await page.locator('#evaluation-attempt option').count(), 5);
    assert.equal(await page.locator('#explain').isDisabled(), true);
    await page.locator('#evaluation-attempt').selectOption('2'); await page.locator('#evaluation-open').click();
    const historical = page.locator('[data-claim-id="source_observations:1"]');
    await historical.waitFor({ state: 'visible' });
    assert.match(await historical.locator('.source-scope').textContent(), /历史来源/);
    await historical.locator('.historical-evidence summary').first().click();
    assert.ok((await historical.locator('.historical-evidence pre').first().textContent()).includes('source_pointer'));
    await historical.locator('.claim-rating').selectOption('unsupported');
    await historical.locator('.claim-reason').fill('历史引用不能证明当前注入 <img src=x onerror="window.__eval_xss=1">');
    await page.locator('#claim-reviewer').fill('Synthetic UI analyst');
    await page.locator('#claim-save').click();
    await page.waitForFunction(() => document.getElementById('claim-status').textContent.includes('已保存 · 版本 1'));
    assert.match(await page.locator('#evaluation-status').textContent(), /1 \/ 5/);
    // Unsaved edits must not replace the selected persisted judgment in ratings.json.
    await historical.locator('.claim-rating').selectOption('supported');
    await page.locator('#evaluation-reviewer').fill('Synthetic coordinator');
    const pending = page.waitForEvent('download'); await page.locator('#evaluation-export').click();
    const download = await pending, zipPath = path.join(artifacts, 'evaluation-review.zip'); await download.saveAs(zipPath);
    const extracted = path.join(temporary, 'export'); fs.mkdirSync(extracted);
    execFileSync(python, ['-m', 'zipfile', '-e', zipPath, extracted]);
    const ratings = JSON.parse(fs.readFileSync(path.join(extracted, 'ratings.json')));
    const binding = JSON.parse(fs.readFileSync(path.join(extracted, 'bindings.json')));
    assert.equal(ratings.items.filter(item => item.rating === 'unsupported').length, 1);
    assert.equal(ratings.items.filter(item => item.rating === 'supported').length, 0);
    assert.equal(binding.selections[0].revision, 1); assert.equal(binding.unselected_attempts.length, 4);
    const summary = JSON.parse(execFileSync(python, ['-m', 'artemis_v3.evaluation', 'review', '--run', runPath,
      '--ratings', path.join(extracted, 'ratings.json')], { encoding: 'utf8' }));
    assert.equal(summary.by_source_scope.historical.unsupported, 1);
    fs.copyFileSync(runPath, path.join(artifacts, 'evaluation-run.json'));
    for (const filename of ['ratings.json', 'bindings.json', 'summary.json']) fs.copyFileSync(path.join(extracted, filename), path.join(artifacts, filename));
    await page.reload(); await page.locator('#evaluation-panel').waitFor({ state: 'visible' });
    assert.match(await page.locator('#evaluation-status').textContent(), /0 \/ 5/);
    await page.locator('#evaluation-attempt').selectOption('2'); await page.locator('#evaluation-open').click();
    await page.locator('#claim-history-list button').first().waitFor({ state: 'visible' });
    await page.locator('#claim-history-list button').first().click();
    await page.waitForFunction(() => document.getElementById('claim-status').textContent.includes('已保存 · 版本 1'));
    assert.equal(await historical.locator('.claim-rating').inputValue(), 'unsupported');
    await historical.locator('.claim-reason').fill('Revised independent check: historical is not current');
    await page.locator('#claim-save').click();
    await page.waitForFunction(() => document.getElementById('claim-status').textContent.includes('已保存 · 版本 2'));
    assert.match(await page.locator('#metrics').textContent(), /6 \/ 10/);
    await historical.locator('.historical-evidence summary').first().click();
    await page.screenshot({ path: path.join(artifacts, 'evaluation-desktop.png'), fullPage: true });
    await historical.screenshot({ path: path.join(artifacts, 'evaluation-historical-claim.png') });
    // Explicit draft-discard decision protects work while switching attempts.
    await historical.locator('.claim-reason').fill('unsaved correction');
    await page.locator('#evaluation-attempt').selectOption('4');
    page.once('dialog', dialog => dialog.dismiss()); await page.locator('#evaluation-open').click();
    assert.equal(await historical.locator('.claim-reason').inputValue(), 'unsaved correction');
    page.once('dialog', dialog => dialog.accept()); await page.locator('#evaluation-open').click();
    await page.waitForFunction(() => document.getElementById('semantic-content').textContent.includes('outside the supplied context'));
    assert.equal(await page.locator('#claim-controls').isHidden(), true);
    assert.match(await page.locator('#evaluation-status').textContent(), /1 \/ 5/);
    await page.locator('#evaluation-attempt').selectOption('2'); await page.locator('#evaluation-open').click();
    await page.waitForFunction(() => document.getElementById('claim-status').textContent.includes('已保存 · 版本 2'));
    await page.setViewportSize({ width: 390, height: 844 });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: path.join(artifacts, 'evaluation-mobile.png'), fullPage: true });
    await page.locator('#evaluation-clear').click(); assert.match(await page.locator('#evaluation-status').textContent(), /0 \/ 5/);
    assert.equal(await page.evaluate(() => window.__eval_xss), undefined);
    assert.deepEqual(errors, []); assert.deepEqual(unexpected, []);
    assert.equal(calls.filter(value => value === '/api/explain').length, 0);
    assert.deepEqual(JSON.parse(fs.readFileSync(runPath)), recorded);
    console.log('PASS: offline evaluation review, rejected attempts, historical evidence, exact saved/draft revisions, ZIP/CLI parity, reload and mobile');
  } finally {
    if (page && !page.isClosed()) await page.screenshot({ path: path.join(artifacts, 'evaluation-final.png'), fullPage: true }).catch(() => {});
    if (browser) await browser.close(); await stop(child);
    fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
