"""Bounded, readable investigation handoff from revalidated local inputs.

Rendering calls no model, follows no report URLs and changes no investigation state.
HTML is standalone with no executable content; Markdown uses literal source blocks.
"""
from collections import Counter
from datetime import datetime, timezone
import html
import json
import re

from .claim_review import (check_saved_inputs, explanation_claims, list_claim_reviews,
                           prepare_review_draft, review_template, summarize, verify_generation)
from .review import ReviewError, _digest, list_reviews
from .scoring import assess_signatures, propose_adjustment

MAX_APPENDIX = 256
MAX_TIMELINE = 20  # per clock domain
MAX_WARNINGS = 100
MAX_TEXT = 4000
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
RATINGS = {'supported': '有证据支持', 'unsupported': '证据不支持', 'uncertain': '不确定', 'unreviewed': '未核验'}
SCOPES = {'current': '当前来源', 'historical': '历史来源', 'mixed': '跨来源'}
SECTIONS = {'source_observations': '来源观察 · 模型概括', 'hypotheses': '待验证推测', 'adjustment': '模型评分校正理由'}
DECISIONS = {'approve': '批准建议', 'reject': '拒绝建议', 'defer': '暂缓决定'}
CLOCKS = {'utc': '已知时区 · UTC', 'report_clock': '报告时钟 · 时区未知', 'undated': '时间缺失或无效'}

STYLE = '''
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#eff3f5;color:#193340;font:15px/1.7 system-ui,"Microsoft YaHei",sans-serif}
main{max-width:1000px;margin:30px auto;padding:40px 48px;background:white;border:1px solid #dbe4e8;border-radius:10px}
h1{font-size:30px;margin:0 0 18px}h2{font-size:21px;margin:38px 0 15px;padding-bottom:8px;border-bottom:2px solid #dbe8e9}h3{font-size:17px;margin:25px 0 10px}
p,dd,li,code{overflow-wrap:anywhere}a{color:#126a77;overflow-wrap:anywhere}a:focus-visible{outline:3px solid #58aab5}
.notice{border-left:4px solid #c18b40;background:#fff8e9;padding:12px 16px}.muted{color:#617680}.claim{border:1px solid #dae5e8;border-radius:7px;padding:5px 20px 15px;margin:18px 0}
dl{display:grid;grid-template-columns:175px minmax(0,1fr);gap:7px 20px}dt{color:#617680;font-size:13px}dd{margin:0;white-space:pre-wrap}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f6;padding:14px;border-radius:5px;font:12px/1.7 ui-monospace,monospace}
ul{padding-left:22px}.refs a{display:inline-block;margin:2px 12px 2px 0}footer{margin-top:35px;color:#617680;font-size:12px}
@media(max-width:650px){main{margin:0;padding:24px 18px;border:0;border-radius:0}dl{grid-template-columns:1fr;gap:3px}dd{margin-bottom:8px}h1{font-size:25px}.claim{padding:3px 13px 12px}}
@page{size:A4;margin:18mm}@media print{body{background:white;font-size:10pt}main{margin:0;padding:0;border:0;max-width:none}h1{font-size:22pt}h2,h3{break-after:avoid}pre{font-size:8pt}a{color:inherit;text-decoration:none}.claim,.evidence-excerpt{break-inside:avoid}}
'''


def _bounded(value):
    text = '未提供' if value is None else str(value)
    clipped = len(text) > MAX_TEXT
    text = text[:MAX_TEXT]
    # Expose invisible directional/control characters; preserve ordinary whitespace.
    text = ''.join(f'\\u{ord(c):04x}' if ((ord(c) < 32 and c not in '\n\r\t') or ord(c) == 127 or
                   0xD800 <= ord(c) <= 0xDFFF or 0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069)
                   else c for c in text)
    return text + ('\n[展示已截断；完整规范化数据见 JSON 导出]' if clipped else '')


def _fence(text, language='text'):
    marker = '`' * max(3, 1 + max((len(run) for run in re.findall(r'`+', text)), default=0))
    return f'{marker}{language}\n{text}\n{marker}\n'


class _Writer:
    """One document structure for both formats; all source strings stay literal."""
    def __init__(self, format):
        self.format = format
        self.parts = []

    def heading(self, level, title, anchor=None):
        if self.format == 'html':
            # Anchors are generated identifiers, never source data.
            attr = f' id="{anchor}"' if anchor else ''
            self.parts.append(f'<h{level}{attr}>{html.escape(title)}</h{level}>')
        else:
            self.parts.append('#' * level + ' ' + title + '\n')

    def note(self, text, *, warning=False):
        if self.format == 'html':
            self.parts.append('<p class="' + ('notice' if warning else 'muted') + '">' + html.escape(text) + '</p>')
        else:
            self.parts.append(text + '\n')  # Only developer-authored notices use this method.

    def text(self, text):
        text = _bounded(text)
        self.parts.append('<p>' + html.escape(text) + '</p>' if self.format == 'html' else _fence(text))

    def facts(self, values):
        if self.format == 'html':
            self.parts.append('<dl>' + ''.join('<dt>' + html.escape(key) + '</dt><dd>' + html.escape(_bounded(value)) + '</dd>'
                                               for key, value in values) + '</dl>')
        else:
            for key, value in values:
                text = _bounded(value)
                if '\n' in text or '\r' in text:
                    self.parts.append('**' + key + '**\n\n' + _fence(text))
                else:
                    marker = '`' * (1 + max((len(run) for run in re.findall(r'`+', text)), default=0))
                    self.parts.append('**' + key + '**: ' + marker + ' ' + text + ' ' + marker + '\n')

    def code(self, value):
        raw = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
        text = _bounded(raw)
        self.parts.append('<pre>' + html.escape(text) + '</pre>' if self.format == 'html' else _fence(text, 'text'))

    def links(self, entries):
        if self.format == 'html':
            self.parts.append('<p class="refs">' + ' '.join(f'<a href="#{anchor}">{html.escape(label)}</a>'
                                                          for anchor, label in entries) + '</p>')
        else:
            self.parts.append(' · '.join(f'[{label}](#{anchor})' for anchor, label in entries) + '\n')

    def begin_claim(self):
        if self.format == 'html':
            self.parts.append('<article class="claim">')

    def end_claim(self):
        if self.format == 'html':
            self.parts.append('</article>')

    def begin_evidence(self):
        if self.format == 'html':
            self.parts.append('<section class="evidence-excerpt">')

    def end_evidence(self):
        if self.format == 'html':
            self.parts.append('</section>')

    def finish(self):
        body = '\n'.join(self.parts)
        if self.format == 'html':
            body = ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width,initial-scale=1">'
                    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
                    '<meta name="referrer" content="no-referrer"><title>Artemis v3 调查报告</title><style>' + STYLE +
                    '</style></head><body><main>' + body + '</main></body></html>')
        if len(body.encode()) > MAX_OUTPUT_BYTES:
            raise ValueError('Readable report exceeds 8 MiB; use the full JSON export')
        return body


def _score_record(database, review_id, report, catalog, result, packet):
    if not database or catalog is None:
        raise ReviewError('Exporting a saved score decision requires its local review store and ruleset')
    records = list_reviews(database, review_id=review_id, limit=1)
    if not records:
        raise ReviewError('The selected score review was not found')
    record = records[0]
    if (record['source_sha256'] != report.source_sha256 or record['ruleset_sha256'] != catalog.source_sha256 or
            record['ruleset_synthetic'] is not catalog.synthetic or _digest(record['assessment']) != _digest(result['rule_assessment'])):
        raise ReviewError('The selected score review differs from the current report, rules or implementation')
    proposal = record['proposal']
    # The assessment is already recomputed by investigate_payload; the proposal is checked independently below.
    assessment = assess_signatures(report, catalog.rules, version=catalog.version)
    expected = propose_adjustment(report, assessment, delta=proposal['proposed_delta'],
                                  cited_evidence=proposal['cited_evidence'], rationale=proposal['rationale'])
    if (_digest(expected.as_dict()) != _digest(proposal) or record['decision'] not in DECISIONS or
            record['base_score'] != assessment.base_score or
            record['analyst_score'] != (expected.proposed_score if record['decision'] == 'approve' else None) or
            (record['decision'] == 'approve' and expected.status == 'blocked_critical_signal')):
        raise ReviewError('Saved score decision no longer matches the current scoring contract')
    if packet and (record['external_proposal_sha256'] != packet['proposal_sha256'] or
                   _digest(proposal) != _digest(packet['adjustment_proposal'])):
        raise ReviewError('The selected score review belongs to a different imported proposal')
    return record


def prepare_export(result, report, catalog, packet, request, *, review_db=None, receipt_key):
    """Resolve review IDs read-only; never accept browser-supplied review bodies."""
    fields = {'format', 'generation', 'receipt', 'claim_review_id', 'claim_draft', 'score_review_id'}
    if not isinstance(request, dict) or set(request) != fields or request['format'] not in ('markdown', 'html'):
        raise ValueError('Expected the documented readable export request and markdown or html format')
    snapshot = dict(result)
    generation = request['generation']
    if generation is None:
        if any(request[key] is not None for key in ('receipt', 'claim_review_id', 'claim_draft')):
            raise ReviewError('Claim judgments require their exact explanation snapshot')
    else:
        verify_generation(receipt_key, generation, request['receipt'], report, catalog)
        snapshot.update(semantic_review=generation['explanation'], model_status='completed')
        generation_id = review_template(generation)['generation_sha256']
        snapshot['generation_sha256'] = generation_id
        if request['claim_review_id'] is not None:
            if not review_db:
                raise ReviewError('Saved claim judgments require their local review store')
            records = list_claim_reviews(review_db, report, catalog, review_id=request['claim_review_id'], limit=1)
            if not records or records[0]['generation_sha256'] != generation_id:
                raise ReviewError('Selected claim review does not match this generation and source')
            check_saved_inputs(records[0], report, catalog)
            snapshot['claim_review'] = records[0]
        if request['claim_draft'] is not None:
            draft = prepare_review_draft(generation, request['claim_draft'])
            if draft['expected_previous_id'] != request['claim_review_id']:
                raise ReviewError('Draft must be based on the selected saved claim review, or neither may have a review ID')
            snapshot['claim_review_draft'] = draft
    if request['score_review_id'] is not None:
        snapshot['analyst_review'] = _score_record(review_db, request['score_review_id'], report, catalog, result, packet)
    return snapshot


def _claim_rows(snapshot):
    explanation = snapshot.get('semantic_review')
    if not explanation:
        return []
    saved = snapshot.get('claim_review')
    if saved:
        return saved['items']
    return [{**claim, 'rating': 'unreviewed', 'reason': ''} for claim in explanation_claims(explanation)]


def _evidence_view(snapshot, claims):
    report = snapshot['report']
    historical = snapshot.get('semantic_review', {}).get('historical_context')
    available = {item['evidence_id']: ('current', item) for item in report['evidence']}
    for item in historical['evidence'] if historical else []:
        available[item['evidence_id']] = ('historical', item)
    wanted = []
    for claim in claims:
        wanted.extend(claim['evidence_refs'])
    packet = snapshot.get('proposal_review')
    if packet:
        wanted.extend(packet['adjustment_proposal']['cited_evidence'])
    if snapshot.get('analyst_review'):
        wanted.extend(snapshot['analyst_review']['proposal']['cited_evidence'])
    for finding in (snapshot.get('rule_assessment') or {}).get('findings', []):
        wanted.extend(finding['evidence_refs'][:1])  # one representative per finding; total count stays visible
    for clock in CLOCKS:
        wanted.extend(event['evidence_ref'] for event in report['timeline'][clock][:MAX_TIMELINE])
    wanted = list(dict.fromkeys(wanted))
    if any(ref not in available for ref in wanted):
        raise ValueError('A report citation has no matching source evidence')
    included = wanted[:MAX_APPENDIX]
    index = {ref: f'e{number:03}' for number, ref in enumerate(included, 1)}
    return available, wanted, included, index


def render_report(snapshot, format, *, generated_at=None):
    """Render only a snapshot returned by prepare_export, never a pasted external report."""
    if format not in ('markdown', 'html'):
        raise ValueError('Unsupported readable report format')
    w = _Writer(format)
    report = snapshot['report']; assessment = snapshot['rule_assessment']
    explanation = snapshot.get('semantic_review'); saved = snapshot.get('claim_review')
    claims = _claim_rows(snapshot)
    available, wanted, included, index = _evidence_view(snapshot, claims)

    def refs(values):
        linked = [(index[ref], index[ref].upper() + ' · ' + SCOPES[available[ref][0]]) for ref in values if ref in index]
        if linked:
            w.links(linked)
        for ref in values:
            if ref not in index:
                w.facts([('证据 ID（字段未收入本报告，见 JSON）', ref)])

    w.heading(1, 'Artemis v3 调查报告')
    w.note('已有 CAPE 报告的辅助调查；来源记录、模型解释与人工判断分别呈现。最终恶意性结论：尚未记录。')
    if report['synthetic'] or snapshot['ruleset_synthetic']:
        w.note('包含合成演示数据；不得作为真实样本的分析结论。', warning=True)
    w.facts([('导出时间（UTC）', generated_at or datetime.now(timezone.utc).isoformat()),
             ('报告原始字节 SHA-256', report['source_sha256']),
             ('报告声明的样本 SHA-256', snapshot['source_identity'].get('sample_sha256') or '未提供有效值；未核验样本字节'),
             ('报告来源', '合成演示' if report['synthetic'] else '未标记为合成；真实性需独立核验'),
             ('规则来源', '未加载' if assessment is None else '合成规则' if snapshot['ruleset_synthetic'] else '未标记为合成规则'),
             ('规则 SHA-256', snapshot['ruleset_sha256'] or '未加载'),
             ('已规范化来源记录', len(report['evidence']))])
    if format == 'html':
        w.links([('scores', '规则与评分复核'), ('model', '模型解释与核验'), ('pending', '待核查与覆盖'),
                 ('timeline', '时间线概览'), ('evidence', '引用证据')])
    w.heading(2, '规则结果与评分复核', 'scores')
    if assessment is None:
        w.note('未加载规则集，未计算规则分数。')
    else:
        w.facts([('规则原始分数', f"{assessment['base_score']} / 10"), ('规则版本', assessment['ruleset_version']),
                 ('关键规则信号', '存在' if assessment['critical_signals_present'] else '未命中配置的关键规则')])
        w.note('规则点数尚未校准，不是恶意性概率。未命中不证明样本安全。')
        for number, finding in enumerate(assessment['findings'], 1):
            w.heading(3, f'规则命中 {number:02}')
            w.facts([('规则 ID', finding['rule_id']), ('签名名称', finding['signature_name']),
                     ('点数 / 关键信号', f"+{finding['points']} / " + ('是' if finding['critical'] else '否')),
                     ('来源引用总数', len(finding['evidence_refs']))])
            w.note('代表引用：其余命中引用保留在 JSON 导出中。')
            refs(finding['evidence_refs'][:1])
    proposal = snapshot.get('proposal_review')
    if proposal:
        adjustment = proposal['adjustment_proposal']
        w.heading(3, '当前导入的校正建议')
        w.facts([('建议校正值', adjustment['proposed_delta']), ('建议分数', adjustment['proposed_score']),
                 ('门禁状态', '关键负向建议已阻止' if adjustment['status'] == 'blocked_critical_signal' else '须人工决定'),
                 ('理由', adjustment['rationale'])])
        refs(adjustment['cited_evidence'])
    decision = snapshot.get('analyst_review')
    w.heading(3, '所选评分复核记录')
    if not decision:
        w.note('本报告未附评分复核决定；模型建议与逐条支持判断均不代表批准降分。')
    else:
        w.facts([('决定', DECISIONS[decision['decision']]), ('复核人（本地声明）', decision['reviewer']),
                 ('复核时间', decision['reviewed_at']), ('记录 ID', decision['review_id']), ('修订版本', decision['revision']),
                 ('所审建议校正值', decision['proposal']['proposed_delta']), ('所审建议理由', decision['proposal']['rationale']),
                 ('复核理由', decision['reason']), ('人工批准分数', decision['analyst_score'] if decision['analyst_score'] is not None else '未批准'),
                 ('保留的规则原始分数', decision['base_score'])])
        refs(decision['proposal']['cited_evidence'])
        w.note('展示选定的历史修订；不宣称它是数据库的最新决定。')

    w.heading(2, '模型解释与逐条核验', 'model')
    if not explanation:
        w.note('本报告未附模型解释。')
    else:
        w.facts([('模型', explanation['model']), ('模型权重摘要', explanation['model_digest']),
                 ('提示词版本', explanation['prompt_version']), ('上下文 SHA-256', explanation['context_sha256']),
                 ('模型响应 SHA-256', explanation['model_response_sha256']), ('解释快照 SHA-256', snapshot.get('generation_sha256')),
                 ('当前证据进入上下文', f"{len(explanation['supplied_evidence_ids'])} / {explanation['total_evidence_count']}"),
                 ('当前证据未进入上下文', explanation['omitted_evidence_count'])])
        historical = explanation.get('historical_context')
        if historical:
            w.facts([('历史报告 SHA-256', historical['report_sha256']),
                     ('历史来源进入上下文', f"{len(historical['evidence'])} / {historical['total_evidence_count']}"),
                     ('历史来源未进入上下文', historical['omitted_evidence_count'])])
            w.note('历史关联依据报告声明的目标样本哈希；历史行为不能据此认定为当前行为。', warning=True)
        w.note('引用成员校验不证明文字真实；有支持的推测仍保留待验证性质。')
        summary = summarize(claims)
        w.facts([('已保存核验覆盖', f"{summary['reviewed']} / {summary['total']}"),
                 *[(label, summary['counts'][rating]) for rating, label in RATINGS.items()]])
        if saved:
            w.facts([('核验人（本地声明）', saved['reviewer']), ('保存时间', saved['reviewed_at']),
                     ('核验记录 ID', saved['review_id']), ('修订版本', saved['revision'])])
            w.note('以下为选定的已保存修订；未保存编辑另列为草稿，不进入这些计数。')
        else:
            w.note('未附已保存的逐条核验；所有模型条目保持未核验。')
        for number, claim in enumerate(claims, 1):
            w.begin_claim(); w.heading(3, f'C{number:02}', f'c{number:02}')
            w.facts([('条目类型 / 引用归属', SECTIONS[claim['section']] + ' / ' + SCOPES[claim['source_scope']]),
                     ('已保存判断', RATINGS[claim['rating']])])
            w.text(claim['text'])
            if claim['verification']:
                w.facts([('模型提出的验证方法', claim['verification'])])
            refs(claim['evidence_refs'])
            if claim['reason']:
                w.facts([('人工核验理由', claim['reason'])])
            if claim['section'] == 'adjustment':
                adjustment = explanation['proposal_review']['adjustment_proposal']
                w.facts([('模型建议校正值', adjustment['proposed_delta']), ('模型建议分数', adjustment['proposed_score']),
                         ('门禁状态', '关键负向建议已阻止' if adjustment['status'] == 'blocked_critical_signal' else '须人工决定')])
                w.note('支持这段理由不会批准评分调整；评分决定见独立复核记录。')
            w.end_claim()
        w.heading(3, '模型声明的局限')
        for limitation in explanation['limitations']:
            w.text(limitation)

    draft = snapshot.get('claim_review_draft')
    if draft:
        w.heading(2, '未保存的核验草稿')
        w.note('以下为尚未保存、可能未填写完整的编辑内容，不属于已保存核验或评分决定。', warning=True)
        w.facts([('草稿填写人（本地声明）', draft['reviewer'] or '未填写'),
                 ('基于的核验记录 ID', draft['expected_previous_id'] or '无')])
        for number, item in enumerate(draft['items'], 1):
            w.heading(3, f'草稿 C{number:02}')
            w.facts([('草稿选择', RATINGS[item['rating']]), ('草稿理由', item['reason'] or '未填写')])
            w.links([(f'c{number:02}', f'查看 C{number:02} 原陈述与引用')])

    w.heading(2, '待核查条目与覆盖缺口', 'pending')
    pending = [(f'c{number:02}', f"C{number:02} · {SCOPES[claim['source_scope']]} · {RATINGS[claim['rating']]}")
               for number, claim in enumerate(claims, 1) if claim['rating'] != 'supported']
    w.note(f'根据所选已保存核验，仍有 {len(pending)} 条不支持、不确定或未核验的模型条目。')
    if pending:
        w.links(pending)
    w.note('此列表由核验状态整理，不替代分析人员制定后续调查与最终结论。')
    w.facts([('来源解析告警总数', len(report['warnings'])), ('此报告展示告警', min(MAX_WARNINGS, len(report['warnings'])))])
    for warning in report['warnings'][:MAX_WARNINGS]:
        w.text(warning)
    if not report['warnings']:
        w.note('已支持字段无解析告警；不证明沙箱捕获了完整行为。')

    w.heading(2, '当前来源时间线概览', 'timeline')
    w.note('仅包括已支持的进程与 API 时间字段；各时间域分别排序，相同时刻不推断因果。')
    for clock, label in CLOCKS.items():
        events = report['timeline'][clock]
        w.heading(3, label)
        w.note(f'展示前 {min(MAX_TIMELINE, len(events))} / {len(events)} 条。')
        for event in events[:MAX_TIMELINE]:
            item = available[event['evidence_ref']][1]
            w.facts([('时间 / 状态', event['normalized_time'] or event['time_status']),
                     ('来源记录', item['data'].get('api') or item['data'].get('process_name') or item['source_pointer'])])
            refs([event['evidence_ref']])

    w.heading(2, '引用证据字段摘录', 'evidence')
    w.note(f'本报告包含 {len(included)} / {len(wanted)} 条选用引用的字段摘录（最多 {MAX_APPENDIX} 条）。'
           f'每项最多展示 {MAX_TEXT} 个字符；截断会明确标记。完整规范化记录、时间线和告警见 JSON 导出。')
    w.note('摘录优先保留模型与人工决定的引用，然后是每条规则的代表记录和时间线概览。来源字段仍是报告陈述。')
    for ref in included:
        scope, item = available[ref]
        w.begin_evidence()
        w.heading(3, index[ref].upper(), index[ref])
        w.facts([('来源', SCOPES[scope]), ('证据 ID', ref), ('原始 JSON 位置', item['source_pointer']), ('类型', item['category'])])
        w.code(item)
        w.end_evidence()
    counts = Counter(item['category'] for item in report['evidence'])
    w.heading(3, '当前来源记录类型计数')
    w.facts(sorted(counts.items()))
    w.note('报告与规则原始字节请另行保留。本导出不执行样本、不调用模型；核验身份为本地声明，哈希不证明来源真实。')
    return w.finish()
