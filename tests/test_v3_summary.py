"""Processed summary contract only; synthetic sources and no sample execution."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from artemis_v3.cape import CapeReportError, SUMMARY_FIELDS, parse_cape_report
from artemis_v3.case_store import open_case, save_case
from artemis_v3.claim_review import check_saved_inputs, issue_receipt, record_claim_review, review_template
from artemis_v3.reporting import prepare_export, render_report
from artemis_v3.ruleset import parse_ruleset
from artemis_v3.scoring import assess_signatures
from artemis_v3.semantic import SemanticError, SYSTEM_PROMPT, explain
from artemis_v3.storage import verify
from artemis_v3.workbench import investigate_payload
from test_v3_semantic import StubProvider, output

FIXTURES = Path(__file__).parent / 'fixtures'
FIXTURE = FIXTURES / 'cape_summary_synthetic.json'


def encode(value):
    return json.dumps(value, ensure_ascii=False).encode()


class BehaviorSummaryTests(unittest.TestCase):
    def setUp(self):
        self.raw = FIXTURE.read_bytes(); self.source = json.loads(self.raw)
        self.report = parse_cape_report(self.raw, synthetic=True)

    def test_each_summary_evidence_resolves_to_exact_string_without_attribution(self):
        rows = [row for row in self.report.evidence if row.category.endswith('_summary')]
        self.assertEqual(len(rows), 9)
        for row in rows:
            key, index = row.source_pointer.split('/')[-2:]
            self.assertEqual(row.evidence_id, hashlib.sha256(self.raw).hexdigest() + '#' + row.source_pointer)
            self.assertEqual(row.data, {'reported_operation': key,
                SUMMARY_FIELDS[key][1]: self.source['behavior']['summary'][key][int(index)]})
            self.assertEqual(row.category, SUMMARY_FIELDS[key][0]); self.assertIsNone(row.process_ref)
        payload = self.report.as_dict()
        self.assertEqual(payload['schema_version'], 'cape-evidence/3')
        self.assertEqual(payload['verdict'], 'not_assessed')
        self.assertEqual(len(payload['timeline']['report_clock']), 2)
        self.assertIn('not unique actions', payload['summary_notice'])

    def test_coverage_distinguishes_missing_empty_and_reported(self):
        coverage = self.report.behavior_summary
        self.assertEqual(set(coverage), set(SUMMARY_FIELDS))
        for key, state, count in [('read_keys','absent',0),('started_services','empty',0),('write_keys','reported',2)]:
            self.assertEqual(coverage[key], {'state':state,'record_count':count,'source_pointer':'/behavior/summary/'+key})
        source = copy.deepcopy(self.source); source['behavior']['summary']['read_keys'] = []
        self.assertEqual(parse_cape_report(encode(source)).behavior_summary['read_keys']['state'], 'empty')

    def test_optional_absence_does_not_fabricate_summary_events(self):
        report = parse_cape_report(b'{"behavior":{}}')
        self.assertEqual(report.evidence, [])
        self.assertTrue(all(item['state']=='absent' for item in report.behavior_summary.values()))
        self.assertEqual(report.as_dict()['status'], 'partial')
        report = parse_cape_report(encode({'behavior':{'summary':{key:[] for key in SUMMARY_FIELDS}}}))
        self.assertTrue(all(item['state']=='empty' for item in report.behavior_summary.values()))
        self.assertFalse(any(row.category.endswith('_summary') for row in report.evidence))

    def test_every_supported_field_rejects_malformed_containers_and_values(self):
        for key in SUMMARY_FIELDS:
            for value in (None, '', {}, [False], [1], [{}], [[]], ['valid', None]):
                with self.subTest(key=key,value=value), self.assertRaises(CapeReportError):
                    parse_cape_report(encode({'behavior':{'summary':{key:value}}}))

    def test_duplicate_case_unicode_and_control_text_are_retained_as_source_records(self):
        values = ['Global\\Mutex','Global\\Mutex','global\\mutex','安装程序\u0000\u202e']
        report = parse_cape_report(encode({'behavior':{'summary':{'mutexes':values}}}))
        self.assertEqual([row.data['value'] for row in report.evidence], values)
        self.assertEqual(len({row.evidence_id for row in report.evidence}), 4)
        self.assertEqual(report.as_dict()['timeline']['undated'], [])
        self.assertEqual(report.behavior_summary['mutexes']['record_count'], 4)

    def test_failed_call_and_service_summary_are_independent_source_assertions(self):
        call = next(row for row in self.report.evidence if row.category=='api_call')
        service = next(row for row in self.report.evidence if row.category=='service_summary')
        self.assertFalse(call.data['status']); self.assertEqual(call.data['return'],'0x00000000')
        self.assertEqual(service.data, {'reported_operation':'created_services','value':'SyntheticSetupService'})
        self.assertNotIn('success',service.data); self.assertNotIn('timestamp',service.data)
        self.assertIsNone(service.process_ref)
        self.assertIn('汇总名称不是成功证据', SYSTEM_PROMPT)

    def test_summary_records_share_the_existing_resource_budget(self):
        with patch('artemis_v3.cape.MAX_RECORDS',4), self.assertRaises(CapeReportError):
            parse_cape_report(encode({'behavior':{'summary':{'mutexes':['m']*5}}}))
        with patch('artemis_v3.cape.MAX_NODES',4), self.assertRaises(CapeReportError):
            parse_cape_report(self.raw)

    def test_summary_strings_never_trigger_network_or_process_execution(self):
        with patch('socket.socket',side_effect=AssertionError('network forbidden')), \
             patch('subprocess.Popen',side_effect=AssertionError('execution forbidden')):
            report = parse_cape_report(self.raw)
            markdown = report.as_markdown()
        self.assertIn('<img src=x', next(row.data['value'] for row in report.evidence if row.category=='command_summary'))
        self.assertNotIn('<img src=x',markdown)

    def test_explicit_model_selection_keeps_summary_citation_and_omission_contracts(self):
        selected = next(row.evidence_id for row in self.report.evidence if row.category=='registry_summary')
        provider = StubProvider(output(selected))
        result,_ = explain(self.report,provider,evidence_ids=[selected])
        self.assertEqual(result['source_observations'][0]['evidence_refs'],[selected])
        self.assertEqual(result['omitted_evidence_count'],len(self.report.evidence)-1)
        self.assertEqual(provider.context['evidence'][0]['category'],'registry_summary')
        self.assertEqual(result['prompt_version'],'artemis-semantic/4')
        other = next(row.evidence_id for row in self.report.evidence if row.category=='service_summary')
        with self.assertRaises(SemanticError):
            explain(self.report,StubProvider(output(other)),evidence_ids=[selected])

    def test_critical_score_and_negative_gate_do_not_change_with_summary_counts(self):
        rules = parse_ruleset(encode({'version':'synthetic-critical/1','synthetic':True,'rules':[
            {'rule_id':'DEMO-CRITICAL','signature_name':'synthetic_behavior','points':8,'critical':True}]}))
        source = copy.deepcopy(self.source); source['behavior'].pop('summary')
        without = parse_cape_report(encode(source),synthetic=True)
        self.assertEqual(assess_signatures(self.report,rules.rules,version=rules.version).base_score,
                         assess_signatures(without,rules.rules,version=rules.version).base_score)
        ref = next(row.evidence_id for row in self.report.evidence if row.category=='command_summary')
        value = output(ref); value['adjustment'] = {'delta':-5,'rationale':'Synthetic installer narrative','cited_evidence':[ref]}
        result,_ = explain(self.report,StubProvider(value),catalog=rules,evidence_ids=[ref])
        proposal = result['proposal_review']['adjustment_proposal']
        self.assertEqual(proposal['status'],'blocked_critical_signal'); self.assertEqual(proposal['applied_score'],8)

    def test_old_archive_reopens_exact_bytes_when_new_parser_adds_summary_records(self):
        legacy = copy.deepcopy(self.report); legacy.schema_version = 'cape-evidence/2'
        legacy.evidence = [row for row in legacy.evidence if row.category not in
                           ('registry_summary','service_summary','mutex_summary','command_summary','resolved_api_summary')]
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory)/'cases.sqlite'
            with patch('artemis_v3.case_store.parse_cape_report',return_value=legacy):
                saved = save_case(database,self.raw,synthetic=True)
            metadata,raw,_ = open_case(database,saved['case']['case_id'])
            self.assertEqual(raw,self.raw)
            self.assertLess(metadata['evidence_count'],len(parse_cape_report(raw,synthetic=True).evidence))
            self.assertEqual(verify('case',database)['records'],{'cases':1})

    def test_saved_cited_evidence_survives_new_unrelated_summary_coverage(self):
        legacy = copy.deepcopy(self.report); legacy.schema_version = 'cape-evidence/2'
        legacy.evidence = [row for row in legacy.evidence if not row.category.endswith('_summary')]
        generation = {'explanation':explain(legacy,StubProvider())[0],'suggestion_file_b64':None}
        generation['explanation']['prompt_version'] = 'artemis-semantic/3'  # historical snapshot, not a current model run
        request = review_template(generation); request['reviewer'] = 'synthetic analyst'
        secret = secrets.token_bytes(32)
        with tempfile.TemporaryDirectory() as directory:
            record = record_claim_review(Path(directory)/'reviews.sqlite',legacy,None,generation,
                issue_receipt(secret,generation),secret,request)
            check_saved_inputs(record,self.report,None)

    def test_readable_exports_disclose_summary_coverage_and_escape_command_text(self):
        result,report,catalog,packet = investigate_payload({'report':base64.b64encode(self.raw).decode(),'synthetic':True})
        for format in ('html','markdown'):
            request = {'format':format,'generation':None,'receipt':None,'claim_review_id':None,'claim_draft':None,'score_review_id':None}
            snapshot = prepare_export(result,report,catalog,packet,request,receipt_key=b'synthetic')
            text = render_report(snapshot,format)
            self.assertIn('行为汇总覆盖',text); self.assertIn('字段缺失',text); self.assertIn('明确为空',text)
            if format=='html': self.assertNotIn('<img src=x',text)
            self.assertEqual(snapshot['report']['behavior_summary']['write_keys']['record_count'],2)


if __name__=='__main__':
    unittest.main()
