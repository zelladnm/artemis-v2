'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="artemis-token"]').content;
const reviewEnabled = document.querySelector('meta[name="review-enabled"]').content === 'true';
let inputs = {}, result = null, selected = new Set(), busy = false;
const versions = {};
let modelConfig = { model_enabled: false };
function updateModelControls() {
  $('explain').disabled = busy || !result || !modelConfig.model_enabled;
  $('model-note').textContent = modelConfig.model_enabled ? '本地模型已配置' : '模型未配置';
  $('archive-save').disabled = busy || !result || !modelConfig.archive_enabled;
  for (const id of ['archive-recent', 'archive-search', 'archive-kind', 'archive-sha', 'archive-title']) $(id).disabled = busy || !modelConfig.archive_enabled;
  for (const node of $('archive-list').querySelectorAll('button')) node.disabled = busy;
  $('archive-note').textContent = modelConfig.archive_enabled ? '归档已启用。点击“归档来源”后写入本地存储。' : '启动时配置 --case-db 后可保存和重新打开报告。';
}
api('/api/config').then(config => { modelConfig = config; updateModelControls(); }).catch(() => {});
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
  $('analyze').textContent = value ? '处理中…' : '开始调查';
  updateModelControls();
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
  result = null; selected.clear(); $('case').hidden = true; $('empty').hidden = false;
  $('review-result').textContent = ''; message();
}
async function readFile(input, name, limit) {
  const version = versions[name] = (versions[name] || 0) + 1;
  clearCase(); delete inputs[name]; setBusy(busy);
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
$('synthetic').addEventListener('change', () => { inputs.synthetic = $('synthetic').checked; clearCase(); });
async function analyze() {
  message(); setBusy(true);
  try { result = await api('/api/analyze', inputs); selected.clear(); render(); showTab('overview'); }
  catch (error) { clearCase(); message(error.message); }
  finally { setBusy(false); }
}
$('analyze').addEventListener('click', analyze);
$('demo').addEventListener('click', async () => {
  clearCase(); setBusy(true);
  try {
    inputs = await api('/api/demo');
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
  renderProcesses(); renderTimeline();
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
    result = { ...reviewed, semantic_review: result.semantic_review, suggestion_file_b64: result.suggestion_file_b64 };
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
$('export-json').addEventListener('click', () => { if (result) download(JSON.stringify(result, null, 2), 'artemis-investigation.json', 'application/json'); });
$('export-md').addEventListener('click', () => {
  if (!result) return;
  const escaped = JSON.stringify(result, null, 2).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('`', '&#96;');
  download('# Artemis v3 调查报告\n\n' + (result.report.synthetic || result.ruleset_synthetic ? '**合成演示数据**\n\n' : '') + '规则分数不是恶意性概率；最终结论由分析师复核。\n\n<pre>' + escaped + '</pre>\n', 'artemis-investigation.md', 'text/markdown');
});

function renderSemantic() {
  const target = $('semantic-content'); target.replaceChildren(el('h2', '有证据引用的模型解释'));
  $('use-suggestion').hidden = !result?.suggestion_file_b64;
  if (result?.semantic_error) {
    target.append(el('div', result.semantic_error, 'warning'), el('p', '来源证据和规则分数保留，可继续人工调查。', 'muted')); return;
  }
  const explanation = result?.semantic_review;
  if (!explanation) { target.append(el('p', modelConfig.model_enabled ? '点击“本地模型解释”开始。可先勾选最多 32 条证据；系统会保留关键规则的代表证据。' : '未配置模型，离线调查与复核仍可使用。', 'muted')); return; }
  target.append(el('p', '模型：' + explanation.model + ' · 已发送 ' + explanation.supplied_evidence_ids.length + ' / ' + explanation.total_evidence_count + ' 条证据。', 'muted'));
  target.append(el('div', '引用仅校验了证据存在；模型概括和推测的真实性仍需人工核对。', 'warning'));
  if (explanation.omitted_evidence_count) target.append(el('div', '有 ' + explanation.omitted_evidence_count + ' 条证据未进入模型上下文；不可据此排除其他行为。', 'warning'));
  const byId = new Map(result.report.evidence.map(item => [item.evidence_id, item]));
  for (const [key, title] of [['source_observations', '来源观察 · 模型概括'], ['hypotheses', '待验证推测']]) {
    target.append(el('h2', title));
    if (!explanation[key].length) target.append(el('p', '模型未提供该类条目。', 'muted'));
    for (const entry of explanation[key]) {
      const card = el('div', undefined, 'panel'); card.append(el('p', entry.text));
      if (entry.verification) card.append(el('p', '验证方法：' + entry.verification));
      for (const ref of entry.evidence_refs) if (byId.has(ref)) card.append(evidenceLink(byId.get(ref)));
      target.append(card);
    }
  }
  target.append(el('h2', '局限与后续核查'));
  for (const limitation of explanation.limitations) target.append(el('p', limitation, 'muted'));
  if (explanation.proposal_review) target.append(el('div', '模型提出了校正建议，尚未应用。可送交人工复核。', 'warning'));
}
$('explain').addEventListener('click', async () => {
  if (!result || busy) return;
  setBusy(true); message();
  try {
    const response = await api('/api/explain', { ...inputs, ...(selected.size ? { explanation_evidence_ids: [...selected] } : {}) });
    result = { ...result, model_status: response.model_status, semantic_review: response.semantic_review || null,
      semantic_error: response.semantic_error || null, suggestion_file_b64: response.suggestion_file_b64 || null };
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
    result = { ...response, model_status: 'completed', semantic_review: previous.semantic_review, suggestion_file_b64: previous.suggestion_file_b64 };
    $('proposal-file').value = ''; $('input-status').textContent = '当前建议来自本地模型，待人工复核';
    selected.clear(); render(); showTab('review');
  } catch (error) { message(error.message); }
  finally { setBusy(false); }
});

function renderArchives(response) {
  const target = $('archive-list'); target.replaceChildren();
  const kind = { recent: '最近归档', exact_sample_sha256: '按报告声明的样本 SHA-256 精确匹配', exact_report_sha256: '按报告原始字节 SHA-256 精确匹配' }[response.match_kind];
  $('archive-matches').textContent = kind + ' · 显示 ' + response.cases.length + ' 条（最多 ' + response.limit + ' 条）。';
  if (!response.cases.length) target.append(el('p', '没有找到归档记录。', 'muted'));
  for (const item of response.cases) {
    const card = el('div', undefined, 'archive-record');
    card.append(el('strong', item.title));
    if (item.synthetic || item.ruleset_synthetic) card.append(el('span', '合成数据', 'pill'));
    card.append(el('code', '报告：' + item.report_sha256), el('code', '报告声明的样本：' + (item.sample_sha256 || '未提供有效 SHA-256')),
      el('p', item.created_at + ' · ' + item.evidence_count + ' 条来源证据', 'muted'));
    const button = el('button', '重新打开', 'secondary'); button.type = 'button';
    button.addEventListener('click', async () => {
      if (busy) return;
      setBusy(true); message();
      try {
        const opened = await api('/api/cases/open', { case_id: item.case_id });
        inputs = opened.inputs; result = { ...opened.result, archived_case: opened.archived_case }; selected.clear();
        for (const id of ['report-file', 'rules-file', 'proposal-file']) $(id).value = '';
        $('synthetic').checked = inputs.synthetic;
        $('input-status').textContent = '已从本地归档恢复报告与规则';
        $('archive-status').textContent = '已重新打开：' + item.title;
        render(); showTab('overview');
      } catch (error) { message(error.message); }
      finally { setBusy(false); }
    });
    card.append(button); target.append(card);
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
