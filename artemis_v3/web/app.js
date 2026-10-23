'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="artemis-token"]').content;
const reviewEnabled = document.querySelector('meta[name="review-enabled"]').content === 'true';
let inputs = {}, result = null, selected = new Set(), busy = false;
const versions = {};
let modelConfig = { model_enabled: false };
let historicalSelection = null, archivedChoices = new Map();
let claimDraft = null, claimReceipt = null, claimDirty = false;
let evaluationRun = null, activeEvaluation = null;
const evaluationBindings = new Map();
const ratingLabels = { unreviewed: '未核验', supported: '有证据支持', unsupported: '证据不支持', uncertain: '不确定' };
function historyEligible(item) {
  return Boolean(item && result && modelConfig.model_enabled && result.source_identity?.sample_sha256 &&
    item.sample_sha256 === result.source_identity.sample_sha256 && item.synthetic === result.report.synthetic &&
    item.report_sha256 !== result.report.source_sha256);
}
function updateModelControls() {
  $('explain').disabled = busy || !result || !modelConfig.model_enabled;
  $('model-note').textContent = modelConfig.model_enabled ? '本地模型已配置' : '模型未配置';
  $('archive-save').disabled = busy || !result || !modelConfig.archive_enabled;
  for (const id of ['archive-recent', 'archive-search', 'archive-kind', 'archive-sha', 'archive-title']) $(id).disabled = busy || !modelConfig.archive_enabled;
  for (const node of $('archive-list').querySelectorAll('button')) node.disabled = busy ||
    (node.classList.contains('archive-context') && !historyEligible(archivedChoices.get(node.dataset.caseId)));
  if ($('clear-historical')) $('clear-historical').disabled = busy;
  $('archive-note').textContent = modelConfig.archive_enabled ? '归档已启用。点击“归档来源”后写入本地存储。' : '启动时配置 --case-db 后可保存和重新打开报告。';
}
api('/api/config').then(async config => {
  modelConfig = config; updateModelControls();
  if (config.evaluation_enabled) {
    evaluationRun = await api('/api/evaluation');
    $('evaluation-panel').hidden = false;
    $('evaluation-info').textContent = evaluationRun.suite_name + ' · ' +
      (evaluationRun.mode === 'synthetic_replay' ? '合成回放' : '已记录的本地模型运行') + ' · ' + evaluationRun.run_sha256;
    for (const [index, attempt] of evaluationRun.attempts.entries()) {
      $('evaluation-attempt').append(new Option(attempt.case_id + ' · 第 ' + attempt.iteration + ' 次 · ' + attempt.status, String(index)));
    }
    updateEvaluationControls();
  }
}).catch(error => message(error.message));
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function message(text = '') { $('message').textContent = text; }
function setBusy(value) {
  busy = value;
  for (const id of ['demo', 'report-file', 'rules-file', 'proposal-file', 'synthetic']) $(id).disabled = value;
  $('analyze').disabled = value || !inputs.report;
  $('submit-review').disabled = value || !reviewEnabled || !result?.rule_assessment;
  for (const id of ['export-json', 'export-md', 'export-html']) $(id).disabled = value || !result;
  $('analyze').textContent = value ? '处理中…' : '开始调查';
  updateModelControls();
  updateClaimControls();
  updateEvaluationControls();
}
async function api(path, data) {
  const response = await fetch(path, {
    method: data === undefined ? 'GET' : 'POST',
    headers: { 'X-Artemis-Token': token, ...(data === undefined ? {} : { 'Content-Type': 'application/json' }) },
    ...(data === undefined ? {} : { body: JSON.stringify(data) })
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || '本地请求失败');
  return value;
}
function clearCase() {
  activeEvaluation = null;
  $('evaluation-reference').textContent = '';
  result = null; selected.clear(); $('case').hidden = true; $('empty').hidden = false;
  clearClaims();
  $('review-result').textContent = ''; message();
  updateModelControls();
}
function clearHistoricalSelection() {
  historicalSelection = null; delete inputs.historical_case_id;
  if (result) { delete result.semantic_review; delete result.semantic_error; delete result.suggestion_file_b64; result.model_status = modelConfig.model_enabled ? 'configured' : 'not_configured'; }
  clearClaims();
}
async function readFile(input, name, limit) {
  const version = versions[name] = (versions[name] || 0) + 1;
  clearCase(); delete inputs[name]; setBusy(busy);
  if (name === 'report') clearHistoricalSelection();
  const file = input.files[0];
  if (!file) return;
  if (file.size > limit) { message('所选文件超过大小限制。'); return; }
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (versions[name] !== version) return;
    const chunks = [];
    for (let i = 0; i < bytes.length; i += 32768) chunks.push(String.fromCharCode(...bytes.subarray(i, i + 32768)));
    inputs[name] = btoa(chunks.join(''));
    if (name === 'report') { inputs.synthetic = false; $('synthetic').checked = false; }
    $('input-status').textContent = '文件已选择，点击开始调查';
    setBusy(busy);
  } catch { message('无法读取所选文件。'); }
}
for (const [id, name, limit] of [['report-file', 'report', 10 * 1024 ** 2], ['rules-file', 'ruleset', 64 * 1024], ['proposal-file', 'proposal', 32 * 1024]]) {
  $(id).addEventListener('change', () => readFile($(id), name, limit));
}
$('synthetic').addEventListener('change', () => { inputs.synthetic = $('synthetic').checked; clearHistoricalSelection(); clearCase(); });
async function analyze() {
  activeEvaluation = null;
  $('evaluation-reference').textContent = '';
  message(); setBusy(true);
  try { const response = await api('/api/analyze', inputs); clearClaims(); result = response; selected.clear(); render(); showTab('overview'); }
  catch (error) { clearCase(); message(error.message); }
  finally { setBusy(false); }
}
$('analyze').addEventListener('click', analyze);
$('demo').addEventListener('click', async () => {
  clearCase(); setBusy(true);
  try {
    inputs = await api('/api/demo');
    clearHistoricalSelection();
    for (const id of ['report-file', 'rules-file', 'proposal-file']) $(id).value = '';
    $('synthetic').checked = true;
    $('input-status').textContent = '内置合成演示报告与规则';
    result = await api('/api/analyze', inputs); render(); showTab('overview');
  } catch (error) { message(error.message); }
  finally { setBusy(false); }
});
function showTab(name) {
  for (const node of document.querySelectorAll('.view')) node.hidden = node.id !== name;
  for (const button of $('tabs').querySelectorAll('button')) button.classList.toggle('selected', button.dataset.tab === name);
}
$('tabs').addEventListener('click', event => { if (event.target.dataset.tab) showTab(event.target.dataset.tab); });
function evidenceLink(item) {
  const button = el('button', item.data.api || item.data.process_name || item.source_pointer);
  button.type = 'button';
  button.addEventListener('click', () => { $('search').value = item.source_pointer; $('category').value = ''; renderEvidence(); showTab('evidence'); });
  return button;
}
function render() {
  $('empty').hidden = true; $('case').hidden = false;
  const report = result.report, evidence = report.evidence, assessment = result.rule_assessment;
  $('synthetic-badge').hidden = !report.synthetic && !result.ruleset_synthetic;
  $('case-status').textContent = report.status === 'partial' ? '解析完成 · 存在覆盖缺口' : '报告已解析';
  $('fingerprint').textContent = '报告 SHA-256  ' + report.source_sha256;
  $('sample-fingerprint').textContent = result.source_identity?.sample_sha256 ? '报告声明的样本 SHA-256  ' + result.source_identity.sample_sha256 : '报告未提供有效的目标样本 SHA-256';
  $('metrics').replaceChildren();
  for (const [label, count, description] of [
    ['来源证据', evidence.length, '每条记录可定位原始 JSON'],
    ['进程记录', evidence.filter(x => x.category === 'process').length, '按来源记录区分重复 PID'],
    ['网络记录', evidence.filter(x => x.category.startsWith('network_')).length, 'DNS / HTTP / TCP / UDP'],
    ['规则原始分数', assessment ? assessment.base_score + ' / 10' : '—', assessment ? '研究分数 · 待人工复核' : '未加载规则集']]) {
    const card = el('div', undefined, 'metric'); card.append(el('small', label), el('strong', count), el('span', description)); $('metrics').append(card);
  }
  const overview = $('overview'); overview.replaceChildren();
  const columns = el('div', undefined, 'two-column');
  const findings = el('div', undefined, 'panel'); findings.append(el('h2', '规则与证据'));
  if (!assessment) findings.append(el('p', '导入规则集后可查看确定性规则评分。'));
  else {
    findings.append(el('p', '规则版本：' + assessment.ruleset_version));
    for (const finding of assessment.findings) {
      const line = el('div'); line.append(el('span', '+' + finding.points, 'pill'), el('strong', finding.signature_name));
      findings.append(line, el('p', finding.evidence_refs.length + ' 条来源引用' + (finding.critical ? ' · 关键规则信号' : '')));
    }
    if (!assessment.findings.length) findings.append(el('p', '没有配置规则命中；这不代表样本安全。'));
  }
  const model = el('div', undefined, 'panel'); model.append(el('h2', '辅助研判'), el('p', modelConfig.model_enabled ? '本地模型已配置：' + modelConfig.model + '。点击“本地模型解释”后发送选定证据，结果仍需复核。' : '模型尚未接入。可导入已有的 JSON 校正建议，验证来源后交给人工复核。'), el('p', '分析范围：已有 CAPE 报告的只读解析。本工作台不会执行样本。'));
  columns.append(findings, model); overview.append(columns, el('h2', '数据覆盖与待验证事项'));
  if (!report.warnings.length) overview.append(el('p', '已支持字段无解析告警；这不证明沙箱捕获了完整行为。', 'muted'));
  for (const warning of report.warnings.slice(0, 100)) overview.append(el('div', warning, 'warning'));
  if (report.warnings.length > 100) overview.append(el('p', '完整覆盖告警见导出报告。', 'muted'));
  renderProcesses(); renderTimeline(); renderBehaviorSummary();
  $('category').replaceChildren(new Option('全部类型', ''));
  for (const category of [...new Set(evidence.map(x => x.category))].sort()) $('category').append(new Option(category, category));
  $('search').value = ''; renderEvidence(); renderReview(); renderSemantic();
}
function renderProcesses() {
  const target = $('process'); target.replaceChildren(el('h2', '报告中的父子进程关系'), el('p', '父子关系不能单独证明进程注入；缺失、重复或循环关系不强行补全。最多展示 200 个进程。', 'muted'));
  const processes = result.report.evidence.filter(x => x.category === 'process').slice(0, 200);
  const byRef = new Map(processes.map(x => [x.evidence_id, x]));
  const children = new Map(), parents = new Set();
  for (const link of result.report.process_links) {
    if (!byRef.has(link.parent_ref) || !byRef.has(link.child_ref)) continue;
    if (!children.has(link.parent_ref)) children.set(link.parent_ref, []);
    children.get(link.parent_ref).push(byRef.get(link.child_ref)); parents.add(link.child_ref);
  }
  const stack = processes.filter(x => !parents.has(x.evidence_id)).reverse().map(x => [x, target]);
  const seen = new Set();
  while (stack.length) {
    const [process, container] = stack.pop();
    if (seen.has(process.evidence_id)) continue;
    seen.add(process.evidence_id);
    const node = el('div', undefined, 'process-node'), link = evidenceLink(process);
    link.textContent = 'PID ' + process.data.process_id + ' · ' + (process.data.process_name || '名称未知');
    node.append(link); container.append(node);
    const group = el('div', undefined, 'children'); node.append(group);
    for (const child of [...(children.get(process.evidence_id) || [])].reverse()) stack.push([child, group]);
  }
  if (!processes.length) target.append(el('p', '报告没有已支持的进程记录。', 'empty-note'));
}
function renderTimeline() {
  const target = $('timeline'); target.replaceChildren(el('p', '各时间域分别排列；相同时间保留来源顺序，不推断因果。每组最多展示 200 条。', 'muted'));
  const byId = new Map(result.report.evidence.map(x => [x.evidence_id, x]));
  for (const [domain, title] of [['utc', '已知时区 · UTC'], ['report_clock', '报告时钟 · 时区未知'], ['undated', '时间缺失或无效']]) {
    const events = result.report.timeline[domain]; target.append(el('h2', title + ' (' + events.length + ')'));
    if (!events.length) target.append(el('p', '无该类记录。', 'muted'));
    for (const event of events.slice(0, 200)) {
      const row = el('div', undefined, 'timeline-item');
      row.append(el('code', event.normalized_time || event.time_status), evidenceLink(byId.get(event.evidence_ref))); target.append(row);
    }
  }
}
function renderBehaviorSummary() {
  const target = $('behavior-summary');
  target.replaceChildren(el('h2', '报告中的行为汇总'),
    el('p', '汇总由沙箱加工生成，可能重叠或缺少调用结果。条目本身不证明执行成功、持久化或恶意性；进程与时间须另行核验。', 'muted'));
  const labels = { files: '文件总表', read_files: '读取文件', write_files: '写入文件', delete_files: '删除文件',
    keys: '注册表总表', read_keys: '读取注册表', write_keys: '写入注册表', delete_keys: '删除注册表',
    executed_commands: '命令行', resolved_apis: '解析的 API', mutexes: '互斥体',
    created_services: '创建服务', started_services: '启动服务' };
  const groups = [['file_summary', '文件', ['files', 'read_files', 'write_files', 'delete_files']],
    ['registry_summary', '注册表', ['keys', 'read_keys', 'write_keys', 'delete_keys']],
    ['service_summary', '服务', ['created_services', 'started_services']],
    ['command_summary', '命令行', ['executed_commands']], ['mutex_summary', '互斥体', ['mutexes']],
    ['resolved_api_summary', '解析的 API', ['resolved_apis']]];
  const grid = el('div', undefined, 'two-column summary-grid');
  for (const [category, title, fields] of groups) {
    const card = el('section', undefined, 'panel summary-group'); card.dataset.summaryCategory = category;
    card.append(el('h2', title));
    for (const field of fields) {
      const coverage = result.report.behavior_summary?.[field];
      const state = !coverage ? '未提供覆盖记录' : coverage.state === 'absent' ? '字段缺失 · 覆盖未知' :
        coverage.state === 'empty' ? '明确为空 · 未列出记录' : '有记录 · ' + coverage.record_count + ' 条';
      card.append(el('p', labels[field] + '：' + state, 'muted summary-coverage'));
    }
    const rows = result.report.evidence.filter(item => item.category === category && fields.includes(item.data.reported_operation));
    for (const item of rows.slice(0, 20)) {
      const link = evidenceLink(item); link.classList.add('summary-evidence');
      const value = item.data.path ?? item.data.value;
      link.textContent = labels[item.data.reported_operation] + ' · ' + value.slice(0, 160) + (value.length > 160 ? '…' : '');
      card.append(link);
    }
    if (rows.length) {
      const browse = el('button', '查看全部 ' + rows.length + ' 条来源记录', 'secondary'); browse.type = 'button';
      browse.addEventListener('click', () => { $('search').value = ''; $('category').value = category; renderEvidence(); showTab('evidence'); });
      card.append(browse, el('p', '本页最多展示 20 条；相同值保留各自出处。', 'muted'));
    }
    grid.append(card);
  }
  target.append(grid);
}
function renderEvidence() {
  if (!result) return;
  const query = $('search').value.toLowerCase(), category = $('category').value;
  const matches = result.report.evidence.filter(x => (!category || x.category === category) && JSON.stringify(x).toLowerCase().includes(query));
  $('evidence-count').textContent = '匹配 ' + matches.length + ' 条，展示前 200 条；已选择 ' + selected.size + ' 条复核引用。';
  const target = $('evidence-list'); target.replaceChildren();
  for (const item of matches.slice(0, 200)) {
    const card = el('div', undefined, 'evidence-card'), head = el('div', undefined, 'evidence-head');
    const check = el('input'); check.type = 'checkbox'; check.checked = selected.has(item.evidence_id);
    check.setAttribute('aria-label', '引用 ' + item.source_pointer);
    check.disabled = Boolean(result.proposal_review);
    check.addEventListener('change', () => {
      if (check.checked && selected.size >= 32) { check.checked = false; message('最多选择 32 条证据引用。'); return; }
      if (check.checked) selected.add(item.evidence_id); else selected.delete(item.evidence_id);
      $('previous-id').value = ''; updateCitations();
    });
    head.append(check, el('span', item.category, 'pill'), el('code', item.source_pointer));
    const details = el('details'); details.append(el('summary', '查看原始字段与证据 ID'), el('pre', JSON.stringify(item, null, 2)));
    card.append(head, details); target.append(card);
  }
}
$('search').addEventListener('input', renderEvidence); $('category').addEventListener('change', renderEvidence);
function updateCitations() { $('citation-status').textContent = '已选择 ' + selected.size + ' 条来源证据。' + (result?.proposal_review ? '导入建议的校正值、理由和引用已锁定。' : '到“证据浏览”勾选 1–32 条。'); }
function renderReview() {
  const packet = result.proposal_review, target = $('proposal-summary'); target.replaceChildren();
  $('review-result').textContent = ''; $('previous-id').value = ''; $('reason').value = '';
  for (const id of ['delta', 'rationale']) $(id).readOnly = Boolean(packet);
  if (packet) {
    const proposal = packet.adjustment_proposal;
    selected = new Set(proposal.cited_evidence); $('delta').value = proposal.proposed_delta; $('rationale').value = proposal.rationale;
    const notice = el('div', proposal.status === 'blocked_critical_signal' ? '关键规则信号：负向校正建议不能获批。' : '已校验建议来源；尚未记录人工决定。', 'warning');
    notice.id = 'proposal-decision'; target.append(notice);
    target.append(el('p', '建议导入时的校验结果（人工决定见下方记录）：', 'muted'), el('pre', JSON.stringify(packet, null, 2))); renderEvidence();
  } else { $('delta').value = 0; $('rationale').value = ''; }
  $('review-status').textContent = !reviewEnabled ? '当前为只读模式。启动时配置 --review-db 后可保存本地复核历史。' : !result.rule_assessment ? '请先加载规则集。' : '身份为本地声明。保存操作会向本地数据库追加记录。';
  updateCitations(); setBusy(busy);
}
$('review-form').addEventListener('submit', async event => {
  event.preventDefault(); if (!result || busy) return;
  if (!selected.size) { message('请先选择来源证据。'); return; }
  const request = { source_sha256: result.report.source_sha256, ruleset_sha256: result.ruleset_sha256,
    delta: Number($('delta').value), cited_evidence: [...selected], rationale: $('rationale').value,
    reviewer: $('reviewer').value, decision: $('decision').value, reason: $('reason').value,
    expected_previous_id: $('previous-id').value.trim() || null };
  setBusy(true); message();
  try {
    const reviewed = await api('/api/review', { ...inputs, review_request: request });
    result = { ...reviewed, semantic_review: result.semantic_review, suggestion_file_b64: result.suggestion_file_b64, claim_review: result.claim_review };
    if (result.semantic_review) result.model_status = 'completed';
    $('review-result').textContent = '已保存：' + reviewed.analyst_review.review_id + ' · 规则原始分数保持 ' + reviewed.analyst_review.base_score;
    if ($('proposal-decision')) $('proposal-decision').textContent = '已保存人工决定：' + ({ approve: '批准建议', reject: '拒绝建议', defer: '暂缓决定' }[reviewed.analyst_review.decision]) + '。详见下方复核记录。';
    $('previous-id').value = reviewed.analyst_review.review_id;
    await history();
  } catch (error) { message(error.message); }
  finally { setBusy(false); }
});
async function history() {
  try {
    const records = (await api('/api/history')).reviews, target = $('history-list'); target.replaceChildren();
    if (!records.length) target.append(el('p', '尚无本地复核记录。', 'muted'));
    for (const record of records) {
      const row = el('div', undefined, 'history-record');
      row.append(el('strong', record.reviewer + ' · ' + record.decision), el('code', record.review_id),
        el('p', record.reason), el('code', record.reviewed_at + ' · 版本 ' + record.revision + ' · 报告 ' + record.source_sha256));
      const details = el('details'); details.append(el('summary', '查看完整复核记录'), el('pre', JSON.stringify(record, null, 2))); row.append(details); target.append(row);
    }
  } catch (error) { message(error.message); }
}
$('history').disabled = !reviewEnabled;
$('history').addEventListener('click', history);
for (const id of ['delta', 'rationale']) $(id).addEventListener('input', () => { $('previous-id').value = ''; });
function download(content, filename, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = el('a'); link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function exportSnapshot() {
  return { ...result, ...(claimDirty ? { claim_review_draft: { status: 'unsaved', ...claimDraft } } : {}) };
}
$('export-json').addEventListener('click', () => { if (result) download(JSON.stringify(exportSnapshot(), null, 2), 'artemis-investigation.json', 'application/json'); });
async function exportReadable(format) {
  if (!result || busy) return;
  setBusy(true); message();
  try {
    const response = await api('/api/export', { ...inputs, export_request: { format,
      generation: result.semantic_review ? { explanation: result.semantic_review, suggestion_file_b64: result.suggestion_file_b64 || null } : null,
      receipt: claimReceipt, claim_review_id: result.claim_review?.review_id || null,
      claim_draft: claimDirty ? claimDraft : null, score_review_id: result.analyst_review?.review_id || null } });
    download(response.content, response.filename, response.mime_type);
  } catch (error) { message(error.message); }
  finally { setBusy(false); }
}
$('export-md').addEventListener('click', () => exportReadable('markdown'));
$('export-html').addEventListener('click', () => exportReadable('html'));

function clearClaims() {
  claimDraft = null; claimReceipt = null; claimDirty = false;
  if (result) delete result.claim_review;
  $('claim-reviewer').value = ''; $('claim-history-list').replaceChildren(); $('claim-history-status').textContent = '';
}
function acceptGeneration(response) {
  clearClaims();
  result = { ...result, model_status: response.model_status || 'restored', semantic_review: response.semantic_review || null,
    semantic_error: response.semantic_error || null, suggestion_file_b64: response.suggestion_file_b64 || null };
  claimReceipt = response.claim_receipt || null;
  claimDraft = response.claim_template || null;
  if (response.claim_review) applyClaimRecord(response.claim_review);
}
function applyClaimRecord(record) {
  result.claim_review = record;
  claimDraft = { generation_sha256: record.generation_sha256, reviewer: record.reviewer, expected_previous_id: record.review_id,
    items: record.items.map(({ claim_id, rating, reason }) => ({ claim_id, rating, reason })) };
  $('claim-reviewer').value = record.reviewer; claimDirty = false;
  if (activeEvaluation && record.generation_sha256 === activeEvaluation.generation_sha256) {
    evaluationBindings.set(activeEvaluation.key, { case_id: activeEvaluation.case_id,
      iteration: activeEvaluation.iteration, review_id: record.review_id });
    updateEvaluationControls();
  }
}
function updateClaimControls() {
  $('claim-save').textContent = activeEvaluation ? '保存并选用于本轮评测' : '保存逐条核验';
  $('claim-controls').hidden = !claimDraft;
  $('claim-history').disabled = busy || !result || !reviewEnabled;
  for (const button of $('claim-history-list').querySelectorAll('button')) button.disabled = busy;
  $('claim-save').disabled = busy || !reviewEnabled || !claimReceipt || !claimDraft?.items.length;
  $('claim-reviewer').disabled = busy || !reviewEnabled;
  for (const field of $('semantic-content').querySelectorAll('.claim-rating, .claim-reason')) field.disabled = busy || !reviewEnabled;
  if (!claimDraft) return;
  const items = claimDraft.items, counts = Object.fromEntries(Object.keys(ratingLabels).map(key => [key, items.filter(item => item.rating === key).length]));
  $('claim-summary').textContent = '已核验 ' + (items.length - counts.unreviewed) + ' / ' + items.length + ' 条 · ' +
    Object.keys(ratingLabels).map(key => ratingLabels[key] + ' ' + counts[key]).join(' · ');
  $('claim-status').textContent = !reviewEnabled ? '启动时配置 --review-db 后可保存逐条核验。' : claimDirty ?
    '有未保存的更改。导出时会单独标为草稿。' : result.claim_review ?
    '已保存 · 版本 ' + result.claim_review.revision + ' · ' + result.claim_review.review_id : '尚未保存，所有条目默认未核验。';
}
function renderClaimFields(card, claimId) {
  const item = claimDraft?.items.find(entry => entry.claim_id === claimId);
  if (!item) return;
  card.dataset.claimId = claimId;
  const fields = el('div', undefined, 'claim-fields');
  const label = el('label', '证据支持程度'), rating = el('select', undefined, 'claim-rating');
  rating.setAttribute('aria-label', '证据支持程度 ' + claimId);
  for (const [value, text] of Object.entries(ratingLabels)) rating.append(new Option(text, value));
  rating.value = item.rating; label.append(rating);
  const reasonLabel = el('label', '核验理由'), reason = el('textarea', undefined, 'claim-reason');
  reason.maxLength = 1000; reason.value = item.reason; reason.required = item.rating !== 'unreviewed';
  reason.setAttribute('aria-label', '核验理由 ' + claimId); reason.placeholder = '说明哪些字段支持或反驳该陈述，或还缺少什么证据'; reasonLabel.append(reason);
  rating.addEventListener('change', () => { item.rating = rating.value; reason.required = item.rating !== 'unreviewed'; claimDirty = true; updateClaimControls(); });
  reason.addEventListener('input', () => { item.reason = reason.value; claimDirty = true; updateClaimControls(); });
  fields.append(label, reasonLabel); card.append(fields);
}
$('claim-reviewer').addEventListener('input', () => {
  if (!claimDraft) return;
  claimDraft.reviewer = $('claim-reviewer').value; claimDirty = true; updateClaimControls();
});
$('claim-form').addEventListener('submit', async event => {
  event.preventDefault(); if (busy || !result?.semantic_review || !claimDraft) return;
  setBusy(true); message();
  try {
    const response = await api('/api/claims/save', { ...inputs,
      generation: { explanation: result.semantic_review, suggestion_file_b64: result.suggestion_file_b64 || null },
      claim_receipt: claimReceipt, claim_request: claimDraft });
    applyClaimRecord(response.claim_review); renderSemantic();
    await claimHistory();
  } catch (error) { message(error.message); }
  finally { setBusy(false); }
});
async function claimHistory() {
  const response = await api('/api/claims/list', { ...inputs,
    ...(activeEvaluation ? { claim_generation_sha256: activeEvaluation.generation_sha256 } : {}) });
  const target = $('claim-history-list'); target.replaceChildren();
  $('claim-history-status').textContent = '匹配 ' + response.reviews.length + ' 条核验记录（最多 ' + response.limit + ' 条）。';
  for (const record of response.reviews) {
    const card = el('div', undefined, 'history-record');
    card.append(el('strong', record.reviewer + ' · 版本 ' + record.revision), el('code', record.reviewed_at),
      el('p', '已核验 ' + record.summary.reviewed + ' / ' + record.summary.total + ' 条'), el('code', record.review_id));
    const open = el('button', activeEvaluation ? '载入并选用于本轮评测' : '载入此核验', 'secondary'); open.type = 'button'; open.disabled = busy;
    open.addEventListener('click', async () => {
      if (busy) return;
      setBusy(true); message();
      try {
        const restored = await api('/api/claims/open', { ...inputs, claim_review_id: record.review_id });
        historicalSelection = null; delete inputs.historical_case_id;
        acceptGeneration(restored); renderSemantic();
      } catch (error) { message(error.message); }
      finally { setBusy(false); }
    });
    card.append(open); target.append(card);
  }
}
$('claim-history').addEventListener('click', async () => {
  if (busy || !result) return;
  setBusy(true); message();
  try { await claimHistory(); }
  catch (error) { message(error.message); }
  finally { setBusy(false); }
});

function renderSemantic() {
  updateClaimControls();
  const target = $('semantic-content'); target.replaceChildren(el('h2', '有证据引用的模型解释'));
  if (historicalSelection) {
    const selection = el('div', undefined, 'panel');
    selection.append(el('p', '已选择历史对照：' + historicalSelection.title), el('code', historicalSelection.report_sha256),
      el('p', '仅在点击“本地模型解释”后发送受限历史证据。同一样本哈希是报告声明，历史行为不等同于当前行为。', 'muted'));
    const clear = el('button', '移除历史对照', 'secondary'); clear.id = 'clear-historical'; clear.type = 'button'; clear.disabled = busy;
    clear.addEventListener('click', () => { if (busy) return; clearHistoricalSelection(); renderSemantic(); });
    selection.append(clear); target.append(selection);
  }
  $('use-suggestion').hidden = !result?.suggestion_file_b64;
  if (result?.semantic_error) {
    target.append(el('div', result.semantic_error, 'warning'), el('p', '来源证据和规则分数保留，可继续人工调查。', 'muted')); return;
  }
  const explanation = result?.semantic_review;
  if (!explanation) { target.append(el('p', modelConfig.model_enabled ? (historicalSelection ? '点击“本地模型解释”开始。历史对照模式为当前证据预留 24 条容量；关键规则代表证据必须保留。' : '点击“本地模型解释”开始。可先勾选最多 32 条证据；关键规则代表证据必须保留。') : '未配置模型，离线调查与复核仍可使用。', 'muted')); return; }
  target.append(el('p', '模型：' + explanation.model + ' · 当前证据已发送 ' + explanation.supplied_evidence_ids.length + ' / ' + explanation.total_evidence_count + ' 条。', 'muted'));
  const historical = explanation.historical_context;
  if (historical) target.append(el('div', '历史来源：' + historical.report_sha256 + ' · 已发送 ' + historical.evidence.length + ' / ' + historical.total_evidence_count + ' 条，遗漏 ' + historical.omitted_evidence_count + ' 条。样本身份仅由报告声明关联。', 'warning'));
  target.append(el('div', '引用仅校验了证据存在；模型概括和推测的真实性仍需人工核对。', 'warning'));
  if (explanation.omitted_evidence_count) target.append(el('div', '有 ' + explanation.omitted_evidence_count + ' 条证据未进入模型上下文；不可据此排除其他行为。', 'warning'));
  const byId = new Map(result.report.evidence.map(item => [item.evidence_id, item]));
  const historicalById = new Map((historical?.evidence || []).map(item => [item.evidence_id, item]));
  for (const [key, title] of [['source_observations', '来源观察 · 模型概括'], ['hypotheses', '待验证推测']]) {
    target.append(el('h2', title));
    if (!explanation[key].length) target.append(el('p', '模型未提供该类条目。', 'muted'));
    for (const [index, entry] of explanation[key].entries()) {
      const card = el('div', undefined, 'panel claim-card');
      const scope = entry.source_scope || (historical ? 'unknown' : 'current');
      const sourceLabel = { current: '当前来源', historical: '历史来源', mixed: '跨来源', unknown: '来源归属未标注' }[scope] || '来源归属未标注';
      card.append(el('span', sourceLabel + (key === 'source_observations' ? '观察' : '推测'), 'pill source-scope'), el('p', entry.text));
      if (entry.verification) card.append(el('p', '验证方法：' + entry.verification));
      for (const ref of entry.evidence_refs) {
        if (byId.has(ref)) { const link = evidenceLink(byId.get(ref)); link.textContent = '当前来源 · ' + link.textContent; card.append(link); }
        if (historicalById.has(ref)) {
          const details = el('details', undefined, 'historical-evidence');
          details.append(el('summary', '历史来源 · ' + historicalById.get(ref).source_pointer),
            el('pre', JSON.stringify(historicalById.get(ref), null, 2))); card.append(details);
        }
      }
      renderClaimFields(card, key + ':' + index); target.append(card);
    }
  }
  target.append(el('h2', '局限与后续核查'));
  for (const limitation of explanation.limitations) target.append(el('p', limitation, 'muted'));
  if (explanation.proposal_review) {
    const proposal = explanation.proposal_review.adjustment_proposal;
    const card = el('div', undefined, 'panel claim-card');
    card.append(el('h2', '评分校正理由 · 事实核验'), el('p', proposal.rationale),
      el('p', '建议校正 ' + proposal.proposed_delta + '；是否采纳须另行记录评分复核决定。', 'muted'));
    for (const ref of proposal.cited_evidence) if (byId.has(ref)) card.append(evidenceLink(byId.get(ref)));
    renderClaimFields(card, 'adjustment:0'); target.append(card);
  }
  updateClaimControls();
}
$('explain').addEventListener('click', async () => {
  if (!result || busy) return;
  setBusy(true); message();
  try {
    const response = await api('/api/explain', { ...inputs, ...(selected.size ? { explanation_evidence_ids: [...selected] } : {}) });
    acceptGeneration(response);
    renderSemantic(); showTab('semantic');
  } catch (error) { message(error.message); }
  finally { setBusy(false); }
});
$('use-suggestion').addEventListener('click', async () => {
  if (!result?.suggestion_file_b64 || busy) return;
  setBusy(true); message();
  const previous = result;
  try {
    const proposedInputs = { ...inputs, proposal: previous.suggestion_file_b64 };
    const response = await api('/api/analyze', proposedInputs);
    inputs = proposedInputs;
    result = { ...response, model_status: 'completed', semantic_review: previous.semantic_review, suggestion_file_b64: previous.suggestion_file_b64, claim_review: previous.claim_review };
    $('proposal-file').value = ''; $('input-status').textContent = '当前建议来自本地模型，待人工复核';
    selected.clear(); render(); showTab('review');
  } catch (error) { message(error.message); }
  finally { setBusy(false); }
});

function renderArchives(response) {
  const target = $('archive-list'); target.replaceChildren();
  archivedChoices = new Map(response.cases.map(item => [item.case_id, item]));
  const kind = { recent: '最近归档', exact_sample_sha256: '按报告声明的样本 SHA-256 精确匹配', exact_report_sha256: '按报告原始字节 SHA-256 精确匹配' }[response.match_kind];
  $('archive-matches').textContent = kind + ' · 显示 ' + response.cases.length + ' 条（最多 ' + response.limit + ' 条）。';
  if (!response.cases.length) target.append(el('p', '没有找到归档记录。', 'muted'));
  for (const item of response.cases) {
    const card = el('div', undefined, 'archive-record');
    card.append(el('strong', item.title));
    if (item.synthetic || item.ruleset_synthetic) card.append(el('span', '合成数据', 'pill'));
    card.append(el('code', '报告：' + item.report_sha256), el('code', '报告声明的样本：' + (item.sample_sha256 || '未提供有效 SHA-256')),
      el('p', item.created_at + ' · 归档时 ' + item.evidence_count + ' 条来源证据', 'muted'));
    const button = el('button', '重新打开', 'secondary'); button.type = 'button';
    button.addEventListener('click', async () => {
      if (busy) return;
      setBusy(true); message();
      try {
        const opened = await api('/api/cases/open', { case_id: item.case_id });
        activeEvaluation = null;
        $('evaluation-reference').textContent = '';
        clearClaims(); inputs = opened.inputs; result = { ...opened.result, archived_case: opened.archived_case }; selected.clear();
        historicalSelection = null;
        for (const id of ['report-file', 'rules-file', 'proposal-file']) $(id).value = '';
        $('synthetic').checked = inputs.synthetic;
        $('input-status').textContent = '已从本地归档恢复报告与规则';
        $('archive-status').textContent = '已重新打开：' + item.title;
        render(); showTab('overview');
      } catch (error) { message(error.message); }
      finally { setBusy(false); }
    });
    const compare = el('button', '用于本次模型解释', 'secondary archive-context'); compare.type = 'button'; compare.dataset.caseId = item.case_id;
    compare.disabled = busy || !historyEligible(item);
    compare.title = '需要已配置模型、相同报告声明样本哈希和合成标记，以及不同报告来源';
    compare.addEventListener('click', () => {
      if (busy || !historyEligible(item)) return;
      clearHistoricalSelection(); historicalSelection = item; inputs.historical_case_id = item.case_id;
      renderSemantic(); showTab('semantic');
    });
    card.append(button, compare); target.append(card);
  }
}
$('archive-save').addEventListener('click', async () => {
  if (!result || busy) return;
  setBusy(true); message();
  try {
    const saved = await api('/api/cases/save', { report: inputs.report, ruleset: inputs.ruleset, synthetic: Boolean(inputs.synthetic), archive_title: $('archive-title').value });
    result.archived_case = saved.case;
    $('archive-status').textContent = (saved.created ? '归档已保存：' : '归档已存在：') + saved.case.title;
    $('archive-panel').open = true;
    renderArchives(await api('/api/cases'));
  } catch (error) { message(error.message); }
  finally { setBusy(false); }
});
$('archive-recent').addEventListener('click', async () => {
  if (busy) return;
  setBusy(true); message();
  try { renderArchives(await api('/api/cases')); }
  catch (error) { message(error.message); }
  finally { setBusy(false); }
});
$('archive-search-form').addEventListener('submit', async event => {
  event.preventDefault(); if (busy) return;
  setBusy(true); message();
  try { renderArchives(await api('/api/cases/search', { kind: $('archive-kind').value, sha256: $('archive-sha').value.trim() })); }
  catch (error) { message(error.message); }
  finally { setBusy(false); }
});

function updateEvaluationControls() {
  for (const id of ['evaluation-attempt', 'evaluation-open', 'evaluation-export', 'evaluation-reviewer']) $(id).disabled = busy || !evaluationRun;
  $('evaluation-clear').disabled = busy || !activeEvaluation || !evaluationBindings.has(activeEvaluation.key);
  if (evaluationRun) $('evaluation-status').textContent = '已为 ' + evaluationBindings.size + ' / ' +
    evaluationRun.attempts.length + ' 次尝试选择已保存修订。仅这些修订进入核验包；失败尝试保留在原运行记录。';
}
$('evaluation-open').addEventListener('click', async () => {
  if (busy || !evaluationRun) return;
  if (claimDirty && !window.confirm('有未保存的核验草稿。放弃草稿并打开所选评测输出？')) return;
  const attempt = evaluationRun.attempts[Number($('evaluation-attempt').value)];
  setBusy(true); message();
  try {
    const opened = await api('/api/evaluation/open', { case_id: attempt.case_id, iteration: attempt.iteration });
    activeEvaluation = null; clearClaims(); historicalSelection = null;
    inputs = opened.inputs; result = opened.result; selected.clear();
    acceptGeneration(opened.result);
    if (claimDraft) activeEvaluation = { case_id: attempt.case_id, iteration: attempt.iteration,
      key: attempt.case_id + ':' + attempt.iteration, generation_sha256: claimDraft.generation_sha256 };
    $('synthetic').checked = inputs.synthetic;
    for (const id of ['report-file', 'rules-file', 'proposal-file']) $(id).value = '';
    $('input-status').textContent = '固定评测输出：' + attempt.case_id + ' · 第 ' + attempt.iteration + ' 次；未重新生成';
    $('evaluation-reference').textContent = '人工参考说明：' + opened.reference_notes;
    render(); showTab('semantic');
    if (activeEvaluation) {
      const chosen = evaluationBindings.get(activeEvaluation.key);
      if (chosen) {
        const restored = await api('/api/claims/open', { ...inputs, claim_review_id: chosen.review_id });
        acceptGeneration(restored); renderSemantic();
      }
      await claimHistory();
    }
  } catch (error) { message(error.message); }
  finally { setBusy(false); }
});
$('evaluation-clear').addEventListener('click', () => {
  if (!busy && activeEvaluation) { evaluationBindings.delete(activeEvaluation.key); updateEvaluationControls(); }
});
$('evaluation-export').addEventListener('click', async () => {
  if (busy || !evaluationRun) return;
  setBusy(true); message();
  try {
    const response = await api('/api/evaluation/export', { run_sha256: evaluationRun.run_sha256,
      reviewer: $('evaluation-reviewer').value, selections: [...evaluationBindings.values()] });
    const bytes = Uint8Array.from(atob(response.content_b64), value => value.charCodeAt(0));
    download(bytes, response.filename, response.mime_type);
    message('评测核验包已导出，包含 ratings.json、summary.json 和具体修订关联记录。');
  } catch (error) { message(error.message); }
  finally { setBusy(false); }
});
