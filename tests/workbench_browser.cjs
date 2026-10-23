/* Real Chromium smoke coverage. Install Playwright only as a CI/developer tool. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { spawn, execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { chromium } = require(process.env.ARTEMIS_PLAYWRIGHT_PATH || 'playwright');

function workbenchOrigin(child) {
  return new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error('Workbench startup timed out')), 15000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`Workbench exited during startup: ${code}`)); });
    child.stdout.on('data', data => {
      output += data;
      const match = output.match(/http:\/\/127\.0\.0\.1:\d+/);
      if (match) { clearTimeout(timer); resolve(match[0]); }
    });
    child.stderr.on('data', data => process.stderr.write(data));
  });
}

async function stopWorkbench(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Workbench shutdown timed out')), 5000);
    child.once('exit', () => { clearTimeout(timer); resolve(); });
    child.kill('SIGTERM');
  });
}

async function readableDownload(page, id, destination) {
  const pending = page.waitForEvent('download');
  await page.locator(id).click();
  const download = await pending;
  await download.saveAs(destination);
  return fs.readFileSync(destination, 'utf8');
}

async function inspectStandaloneReport(browser, filename, artifacts, semantic) {
  const reportPage = await browser.newPage({ viewport: { width: 1280, height: 960 } });
  const reportUrl = pathToFileURL(filename).href, unexpected = [], errors = [];
  reportPage.on('pageerror', error => errors.push(error.message));
  await reportPage.route('**/*', route => {
    if (route.request().url() === reportUrl) return route.continue();
    unexpected.push(route.request().url()); return route.abort();
  });
  try {
    await reportPage.goto(reportUrl);
    assert.equal(await reportPage.locator('h1').textContent(), 'Artemis v3 调查报告');
    assert.equal(await reportPage.locator('script,img,iframe,form,object,embed').count(), 0);
    assert.equal(await reportPage.evaluate(() => window.__artemis_xss || window.__claim_xss || window.__report_xss), undefined);
    assert.ok(await reportPage.locator('a').evaluateAll(links => links.length && links.every(link =>
      link.getAttribute('href').startsWith('#') && document.getElementById(link.getAttribute('href').slice(1)))));
    assert.match(await reportPage.locator('body').textContent(), /最终恶意性结论：尚未记录/);
    assert.match(await reportPage.locator('body').textContent(), semantic ? /拒绝建议/ : /暂缓决定/);
    await reportPage.locator('a[href="#e001"]').first().click();
    assert.equal(new URL(reportPage.url()).hash, '#e001');
    await reportPage.evaluate(() => window.scrollTo(0, 0));
    await reportPage.screenshot({ path: path.join(artifacts, 'report-desktop.png') });
    if (semantic) {
      assert.equal(await reportPage.locator('article.claim').count(), 4);
      assert.match(await reportPage.locator('article.claim').nth(1).textContent(), /历史来源/);
      assert.match(await reportPage.locator('article.claim').nth(1).textContent(), /证据不支持/);
      assert.match(await reportPage.locator('article.claim').nth(2).textContent(), /跨来源/);
      assert.match(await reportPage.locator('body').textContent(), /<img src=x/);
      await reportPage.locator('article.claim').nth(1).screenshot({ path: path.join(artifacts, 'report-historical-claim.png') });
    }
    await reportPage.setViewportSize({ width: 390, height: 844 });
    await reportPage.evaluate(() => window.scrollTo(0, 0));
    assert.ok(await reportPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Standalone report must fit a mobile screen');
    await reportPage.screenshot({ path: path.join(artifacts, 'report-mobile.png') });
    await reportPage.emulateMedia({ media: 'print' });
    await reportPage.pdf({ path: path.join(artifacts, 'investigation-report.pdf'), preferCSSPageSize: true, printBackground: true });
    assert.deepEqual(unexpected, []); assert.deepEqual(errors, []);
  } finally { await reportPage.close(); }
}

(async () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'artemis-ui-'));
  const artifacts = process.env.ARTEMIS_UI_ARTIFACTS || path.join(temporary, 'screenshots');
  fs.mkdirSync(artifacts, { recursive: true });
  const semantic = process.env.ARTEMIS_BROWSER_SEMANTIC === '1';
  const python = process.env.ARTEMIS_PYTHON || 'python';
  const reviewDb = path.join(temporary, 'reviews.sqlite'), caseDb = path.join(temporary, 'cases.sqlite');
  const serverArgs = semantic ? ['tests/serve_semantic_workbench.py'] : ['-m', 'artemis_v3.workbench', '--port', '0'];
  let child = spawn(python, [...serverArgs, '--review-db', reviewDb, '--case-db', caseDb], { stdio: ['ignore', 'pipe', 'pipe'] });
  let browser, page;
  try {
    let origin = await workbenchOrigin(child);
    browser = await chromium.launch({ headless: true });
    page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.setDefaultTimeout(15000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
    await page.goto(origin);
    await page.waitForFunction(() => !document.getElementById('archive-recent').disabled);
    if (semantic) await page.waitForFunction(() => document.getElementById('model-note').textContent.includes('已配置'));
    await page.locator('#demo').click();
    await page.locator('#case').waitFor({ state: 'visible' });
    assert.match(await page.locator('#metrics').textContent(), /1 \/ 10/);
    assert.match(await page.locator('#overview').textContent(), semantic ? /本地模型已配置/ : /模型尚未接入/);
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
    await page.locator('#history-list .history-record').first().waitFor({ state: 'visible' });
    assert.equal(await page.locator('#history-list .history-record').count(), 1);
    const downloadPromise = page.waitForEvent('download');
    await page.locator('#export-json').click();
    const exported = JSON.parse(fs.readFileSync(await (await downloadPromise).path(), 'utf8'));
    assert.equal(exported.rule_assessment.base_score, 1);
    assert.equal(exported.analyst_review.decision, 'defer');
    assert.equal(exported.analyst_review.analyst_score, null);
    const basicReport = path.join(artifacts, 'basic-investigation-report.html');
    const basicHtml = await readableDownload(page, '#export-html', basicReport);
    assert.match(basicHtml, /本报告未附模型解释/);
    assert.ok(basicHtml.includes(exported.report.source_sha256));
    const basicMd = await readableDownload(page, '#export-md', path.join(artifacts, 'basic-investigation-report.md'));
    assert.match(basicMd, /## 规则结果与评分复核/);
    assert.doesNotMatch(basicMd, /<pre>/);
    if (!semantic) await inspectStandaloneReport(browser, basicReport, artifacts, false);

    // Import hostile text and confirm it stays text in the real browser DOM.
    const report = JSON.parse(fs.readFileSync('tests/fixtures/cape_synthetic.json', 'utf8'));
    report.target = { file: { sha256: 'a'.repeat(64) } };
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
    // Save source bytes, reload the page, exact-match the reported sample hash and reopen.
    await page.locator('#archive-panel summary').click();
    await page.locator('#archive-title').fill('<img src=x onerror="window.__archive_xss=1">');
    await page.locator('#archive-save').click();
    await page.waitForFunction(() => document.getElementById('archive-status').textContent.includes('归档已保存'));
    await page.locator('#archive-list .archive-record').first().waitFor();
    assert.equal(await page.locator('#archive-list img').count(), 0);
    const sourceHash = await page.locator('#fingerprint').textContent();
    await page.reload();
    await page.waitForFunction(() => !document.getElementById('archive-recent').disabled);
    await page.locator('#archive-panel summary').click();
    await page.locator('#archive-sha').fill('a'.repeat(64));
    await page.locator('#archive-search').click();
    await page.locator('#archive-list .archive-record').first().waitFor();
    assert.match(await page.locator('#archive-matches').textContent(), /报告声明的样本 SHA-256 精确匹配/);
    assert.equal(await page.locator('#archive-list .archive-record').count(), 1);
    assert.equal(await page.evaluate(() => window.__archive_xss), undefined);
    await page.screenshot({ path: path.join(artifacts, 'archive-mobile.png'), fullPage: true });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'Archive mobile view must not overflow');
    await page.locator('#archive-list button').first().click();
    await page.waitForFunction(() => document.getElementById('input-status').textContent.includes('已从本地归档恢复'));
    assert.equal(await page.locator('#fingerprint').textContent(), sourceHash);
    assert.match(await page.locator('#sample-fingerprint').textContent(), /报告声明的样本 SHA-256/);
    assert.match(await page.locator('#metrics').textContent(), /1 \/ 10/);
    assert.equal(await page.locator('#report-file').inputValue(), '');
    assert.equal(await page.locator('#process img').count(), 0);
    if (semantic) {
      // A second source for the same report-asserted sample enables explicit historical context.
      report.info.id = 2;
      await page.locator('#report-file').setInputFiles({ name: 'current-second-source.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(report)) });
      await page.waitForFunction(() => !document.getElementById('analyze').disabled);
      await page.locator('#synthetic').check();
      await page.locator('#analyze').click();
      await page.locator('#archive-list .archive-context').first().waitFor({ state: 'visible' });
      await page.locator('#archive-list .archive-context').first().click();
      await page.waitForFunction(() => document.getElementById('semantic-content').textContent.includes('已选择历史对照'));
      await page.setViewportSize({ width: 1440, height: 1000 });
      await page.locator('#explain').click();
      await page.waitForFunction(() => document.getElementById('semantic-content').textContent.includes('test:latest'));
      assert.match(await page.locator('#semantic-content').textContent(), /来源观察/);
      assert.match(await page.locator('#semantic-content').textContent(), /待验证推测/);
      assert.match(await page.locator('#semantic-content').textContent(), /历史来源/);
      assert.match(await page.locator('#semantic-content').textContent(), /当前来源观察/);
      assert.match(await page.locator('#semantic-content').textContent(), /历史来源观察/);
      assert.match(await page.locator('#semantic-content').textContent(), /跨来源推测/);
      assert.equal(await page.locator('#semantic-content .historical-evidence').count(), 2);
      await page.locator('#semantic-content .historical-evidence summary').first().click();
      assert.match(await page.locator('#semantic-content .historical-evidence pre').first().textContent(), /evidence_id/);
      assert.equal(await page.locator('#clear-historical').isEnabled(), true);
      const claimCards = page.locator('#semantic-content .claim-card');
      assert.equal(await claimCards.count(), 4);
      assert.match(await page.locator('#claim-summary').textContent(), /已核验 0 \/ 4/);
      await page.locator('#claim-reviewer').fill('UI <img src=x onerror="window.__claim_xss=1">');
      await claimCards.nth(0).locator('.claim-rating').selectOption('supported');
      assert.equal(await page.locator('#claim-form').evaluate(form => form.checkValidity()), false, 'Rated claims require reasons');
      await claimCards.nth(0).locator('.claim-reason').fill('Synthetic current-source check');
      await claimCards.nth(1).locator('.claim-rating').selectOption('unsupported');
      await claimCards.nth(1).locator('.claim-reason').fill('Synthetic rejection: historical records do not establish current behavior');
      await claimCards.nth(2).locator('.claim-rating').selectOption('uncertain');
      await claimCards.nth(2).locator('.claim-reason').fill('Synthetic cross-source hypothesis still needs verification');
      const draftDownload = page.waitForEvent('download');
      await page.locator('#export-json').click();
      const draftExport = JSON.parse(fs.readFileSync(await (await draftDownload).path(), 'utf8'));
      assert.equal(draftExport.claim_review_draft.status, 'unsaved');
      assert.equal(draftExport.claim_review, undefined);
      assert.equal(draftExport.claim_receipt, undefined);
      const draftHtml = await readableDownload(page, '#export-html', path.join(artifacts, 'draft-investigation-report.html'));
      assert.match(draftHtml, /未保存的核验草稿/);
      assert.match(draftHtml, /已保存核验覆盖<\/dt><dd>0 \/ 4/);
      await page.locator('#claim-save').click();
      await page.waitForFunction(() => document.getElementById('claim-status').textContent.includes('已保存 · 版本 1'));
      await page.waitForFunction(() => document.querySelectorAll('#claim-history-list .history-record').length === 1);
      assert.match(await page.locator('#claim-summary').textContent(), /已核验 3 \/ 4/);
      assert.equal(await page.locator('#claim-history-list img').count(), 0);
      assert.equal(await page.evaluate(() => window.__claim_xss), undefined);
      await claimCards.nth(1).screenshot({ path: path.join(artifacts, 'claim-review-desktop.png') });
      await page.screenshot({ path: path.join(artifacts, 'semantic-explanation.png'), fullPage: true });
      await page.setViewportSize({ width: 390, height: 844 });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'Historical explanation must not overflow on mobile');
      await claimCards.nth(1).screenshot({ path: path.join(artifacts, 'claim-review-mobile.png') });
      await page.screenshot({ path: path.join(artifacts, 'historical-mobile.png'), fullPage: true });
      await page.setViewportSize({ width: 1440, height: 1000 });
      await page.locator('#use-suggestion').click();
      await page.waitForFunction(() => document.getElementById('rationale').readOnly);
      // Reviewer identity is deliberately not restored from the source archive.
      await page.locator('#reviewer').fill('UI synthetic analyst');
      assert.equal(await page.locator('#delta').inputValue(), '-1');
      await page.locator('#reason').fill('Synthetic model suggestion rejected after review');
      await page.locator('#decision').selectOption('reject');
      await page.locator('#submit-review').click();
      await page.waitForFunction(() => document.getElementById('review-result').textContent.includes('已保存'));
      await page.waitForFunction(() => document.querySelectorAll('#history-list .history-record').length === 2);
      assert.match(await page.locator('#proposal-decision').textContent(), /已保存人工决定：拒绝建议/);
      const modelDownloadPromise = page.waitForEvent('download');
      await page.locator('#export-json').click();
      const modelExport = JSON.parse(fs.readFileSync(await (await modelDownloadPromise).path(), 'utf8'));
      assert.equal(modelExport.semantic_review.model, 'test:latest');
      assert.equal(modelExport.semantic_review.schema_version, 'artemis-explanation/2');
      assert.equal(modelExport.semantic_review.source_attribution_version, 'artemis-source-attribution/1');
      assert.deepEqual(modelExport.semantic_review.source_observations.map(item => item.source_scope), ['current', 'historical']);
      assert.equal(modelExport.semantic_review.hypotheses[0].source_scope, 'mixed');
      assert.equal(modelExport.semantic_review.historical_context.report_sha256, sourceHash.match(/[a-f0-9]{64}/)[0]);
      assert.notEqual(modelExport.semantic_review.historical_context.report_sha256, modelExport.report.source_sha256);
      assert.equal(modelExport.rule_assessment.base_score, 1);
      assert.equal(modelExport.analyst_review.decision, 'reject');
      assert.equal(modelExport.analyst_review.external_proposal_sha256, modelExport.semantic_review.proposal_review.proposal_sha256);
      assert.equal(modelExport.claim_review.summary.reviewed, 3);
      assert.deepEqual(modelExport.claim_review.summary.counts, { supported: 1, unsupported: 1, uncertain: 1, unreviewed: 1 });
      assert.deepEqual(modelExport.claim_review.items.map(item => item.source_scope), ['current', 'historical', 'mixed', 'current']);
      assert.equal(modelExport.claim_review.score_decision, 'not_recorded_by_claim_review');
      assert.equal(modelExport.claim_review_draft, undefined);
      assert.equal(modelExport.claim_receipt, undefined);
      fs.writeFileSync(path.join(artifacts, 'claim-review-export.json'), JSON.stringify(modelExport, null, 2));
      const reportFilename = path.join(artifacts, 'investigation-report.html');
      const reportHtml = await readableDownload(page, '#export-html', reportFilename);
      assert.ok(reportHtml.includes(modelExport.claim_review.review_id));
      assert.ok(reportHtml.includes(modelExport.analyst_review.review_id));
      assert.match(reportHtml, /已保存核验覆盖<\/dt><dd>3 \/ 4/);
      assert.doesNotMatch(reportHtml, /未保存的核验草稿/);
      assert.doesNotMatch(reportHtml, /claim_receipt/);
      const reportMarkdown = await readableDownload(page, '#export-md', path.join(artifacts, 'investigation-report.md'));
      assert.match(reportMarkdown, /## 模型解释与逐条核验/);
      assert.ok(reportMarkdown.includes(modelExport.semantic_review.context_sha256));
      await inspectStandaloneReport(browser, reportFilename, artifacts, true);
      await page.locator('[data-tab="semantic"]').click();
      await page.locator('#clear-historical').click();
      assert.doesNotMatch(await page.locator('#semantic-content').textContent(), /已选择历史对照/);
      assert.equal(await page.locator('#claim-controls').isVisible(), false);
      // New generation starts unreviewed; saved judgments remain recoverable after a page reload.
      await page.locator('#explain').click();
      await page.waitForFunction(() => !document.getElementById('explain').disabled);
      assert.match(await page.locator('#claim-summary').textContent(), /已核验 0 \/ 3/);
      const archiveSaved = page.waitForResponse(response => response.url().endsWith('/api/cases/save'));
      await page.locator('#archive-save').click();
      assert.equal((await archiveSaved).status(), 200);
      await page.waitForFunction(() => !document.getElementById('archive-save').disabled);
      await page.reload();
      await page.waitForFunction(() => !document.getElementById('archive-recent').disabled);
      await page.locator('#archive-panel summary').click();
      await page.locator('#archive-recent').click();
      await page.locator('#archive-list .archive-record').first().locator('button').first().click();
      await page.waitForFunction(() => document.getElementById('input-status').textContent.includes('已从本地归档恢复'));
      await page.locator('[data-tab="semantic"]').click();
      await page.locator('#claim-history-panel summary').click();
      await page.locator('#claim-history').click();
      await page.locator('#claim-history-list button').first().click();
      await page.waitForFunction(() => document.getElementById('claim-status').textContent.includes('已保存 · 版本 1'));
      assert.match(await page.locator('#claim-summary').textContent(), /已核验 3 \/ 4/);
      assert.equal(await page.locator('.claim-rating').nth(1).inputValue(), 'unsupported');
      assert.match(await page.locator('#semantic-content').textContent(), /历史来源观察/);
      assert.equal(await page.locator('#use-suggestion').isVisible(), true);
      await page.locator('.claim-reason').nth(1).fill('Synthetic revised reason after reopening saved explanation');
      await page.locator('#claim-save').click();
      await page.waitForFunction(() => document.getElementById('claim-status').textContent.includes('已保存 · 版本 2'));
      assert.match(await page.locator('#metrics').textContent(), /1 \/ 10/);

      // Stop every writer, restore both stores at new paths, and resume in a
      // fresh process with no model configured. Receipts cannot survive restart.
      const beforeRecovery = JSON.parse(await readableDownload(page, '#export-json', path.join(artifacts, 'before-recovery.json')));
      await stopWorkbench(child);
      const fileHash = filename => createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
      const originalHashes = [caseDb, reviewDb].map(fileHash), recoveryChecks = [];
      const storage = (action, kind, source, destination) => {
        const args = ['-m', 'artemis_v3.storage', action, '--kind', kind, '--source', source, '--json'];
        if (destination) args.push('--destination', destination);
        const result = JSON.parse(execFileSync(python, args, { encoding: 'utf8', timeout: 45000 }));
        recoveryChecks.push(result);
        if (destination) assert.equal(result.snapshot_sha256, fileHash(destination));
        return result;
      };
      const restoredPaths = {};
      for (const [kind, source] of [['case', caseDb], ['review', reviewDb]]) {
        const backup = path.join(temporary, `${kind}-backup.sqlite`);
        restoredPaths[kind] = path.join(temporary, `${kind}-restored.sqlite`);
        storage('backup', kind, source, backup);
        storage('verify', kind, backup);
        storage('restore', kind, backup, restoredPaths[kind]);
      }
      child = spawn(python, ['-m', 'artemis_v3.workbench', '--port', '0', '--case-db', restoredPaths.case,
        '--review-db', restoredPaths.review], { stdio: ['ignore', 'pipe', 'pipe'] });
      origin = await workbenchOrigin(child);
      await page.goto(origin);
      await page.waitForFunction(() => !document.getElementById('archive-recent').disabled);
      await page.locator('#archive-panel summary').click();
      await page.locator('#archive-recent').click();
      await page.locator('#archive-list .archive-record').first().locator('button').first().click();
      await page.waitForFunction(() => document.getElementById('input-status').textContent.includes('已从本地归档恢复'));
      assert.equal(await page.locator('#explain').isEnabled(), false, 'Recovery must not require a model');
      await page.locator('[data-tab="semantic"]').click();
      await page.locator('#claim-history-panel summary').click();
      await page.locator('#claim-history').click();
      await page.locator('#claim-history-list button').first().click();
      await page.waitForFunction(() => document.getElementById('claim-status').textContent.includes('已保存 · 版本 2'));
      const reopened = JSON.parse(await readableDownload(page, '#export-json', path.join(artifacts, 'reopened-recovery.json')));
      assert.deepEqual(reopened.claim_review, beforeRecovery.claim_review);
      assert.deepEqual(reopened.semantic_review, beforeRecovery.semantic_review);
      assert.deepEqual(reopened.rule_assessment, beforeRecovery.rule_assessment);
      assert.equal(reopened.report.source_sha256, beforeRecovery.report.source_sha256);
      assert.deepEqual(reopened.claim_review.items.map(item => item.source_scope), ['current', 'historical', 'mixed', 'current']);
      await page.locator('.claim-reason').nth(1).fill('Synthetic revision after database recovery without a model');
      await page.locator('#claim-save').click();
      await page.waitForFunction(() => document.getElementById('claim-status').textContent.includes('已保存 · 版本 3'));
      const resumed = JSON.parse(await readableDownload(page, '#export-json', path.join(artifacts, 'resumed-recovery.json')));
      assert.equal(resumed.claim_review.previous_review_id, reopened.claim_review.review_id);
      assert.equal(resumed.claim_review.generation_sha256, reopened.claim_review.generation_sha256);
      assert.equal(resumed.claim_review.base_score, reopened.claim_review.base_score);
      assert.equal(resumed.claim_review.score_decision, 'not_recorded_by_claim_review');
      await page.screenshot({ path: path.join(artifacts, 'recovered-workbench-desktop.png'), fullPage: true });
      await page.setViewportSize({ width: 390, height: 844 });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.locator('#semantic-content .claim-card').nth(1).screenshot({ path: path.join(artifacts, 'recovered-claim-mobile.png') });
      await page.locator('[data-tab="review"]').click();
      await page.locator('#history').click();
      await page.locator('#history-list .history-record').first().waitFor({ state: 'visible' });
      assert.equal(await page.locator('#history-list .history-record').count(), 2);
      assert.match(await page.locator('#history-list').textContent(), /UI synthetic analyst · reject/);
      await stopWorkbench(child);
      assert.deepEqual([caseDb, reviewDb].map(fileHash), originalHashes);
      assert.deepEqual(storage('verify', 'case', restoredPaths.case).records, { cases: 2 });
      assert.deepEqual(storage('verify', 'review', restoredPaths.review).records, { reviews: 2, claim_reviews: 3 });
      fs.writeFileSync(path.join(artifacts, 'storage-recovery-check.json'), JSON.stringify({ synthetic: true,
        model_configured_after_restore: false, originals_unchanged: true,
        restored_generation_sha256: resumed.claim_review.generation_sha256, checks: recoveryChecks }, null, 2));
      console.log('PASS: paired backup/restore, exact saved claims, historical citations and new revision without a model');
    }
    assert.deepEqual(errors, []);
    console.log('PASS: desktop/mobile demo, process links, timeline, citations, persisted review, export and hostile text');
  } finally {
    if (page && !page.isClosed()) await page.screenshot({ path: path.join(artifacts, 'workbench-final.png'), fullPage: true }).catch(() => {});
    if (browser) await browser.close();
    await stopWorkbench(child);
    fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
