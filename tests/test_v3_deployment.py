"""First-machine startup and packaged-source checks; synthetic/local data only."""
import contextlib
import copy
import http.client
import io
import json
import os
from pathlib import Path
from queue import Queue, Empty
import shutil
import subprocess
import sys
import tempfile
from threading import Thread
import time
import unittest
from unittest.mock import patch
import zipfile

from artemis_v3 import deployment as deploy
from tools.build_field_bundle import ROOT_FILES, build

ROOT = Path(__file__).resolve().parents[1]


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='Artemis 空格 '); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / 'private data'

    def settings(self, *args):
        return deploy.settings_for(deploy.parser().parse_args(list(args)), root=self.root)

    def package(self):
        destination = self.root / '应用 package'
        build(destination)
        return destination

    def run_entry(self, root, *args):
        return subprocess.run([sys.executable, '-X', 'utf8', str(root / 'launch.py'), *args],
                              cwd=self.root, capture_output=True, text=True, encoding='utf-8', timeout=20)

    def test_default_lite_and_system_state_are_outside_checkout(self):
        value = self.settings()
        self.assertIsNone(value['ollama_model']); self.assertEqual(value['port'],0)
        self.assertTrue(value['open_browser']); self.assertNotEqual(value['data_dir'],ROOT)
        with patch.object(sys,'platform','win32'), patch.dict(os.environ,{'LOCALAPPDATA':str(self.root)}):
            self.assertEqual(deploy.default_data_dir(),self.root/'ArtemisV3')
        with patch.object(sys,'platform','linux'), patch.dict(os.environ,{'XDG_STATE_HOME':str(self.root)}):
            self.assertEqual(deploy.default_data_dir(),self.root/'artemis-v3')

    def test_config_relative_paths_cli_precedence_and_lite_override(self):
        config = self.root / '配置.json'
        config.write_text(json.dumps({'data_dir':'relative state','port':8765,'open_browser':True,
            'ollama_model':'private-local-model','model_digest':'a'*64}),encoding='utf-8')
        parsed = self.settings('--config',str(config),'--port','0','--no-browser')
        self.assertEqual(parsed['data_dir'],self.root/'relative state')
        self.assertEqual(parsed['port'],0); self.assertFalse(parsed['open_browser'])
        self.assertEqual(parsed['ollama_model'],'private-local-model')
        lite = self.settings('--config',str(config),'--lite','--data-dir',str(self.data))
        self.assertIsNone(lite['ollama_model']); self.assertIsNone(lite['model_digest'])
        self.assertEqual(lite['data_dir'],self.data)

    def test_invalid_duplicate_oversize_and_nonfinite_settings_are_refused(self):
        config = self.root/'settings.json'
        values = [{'port':True},{'port':65536},{'open_browser':1},{'model_timeout':0},
                  {'model_timeout':float('inf')},{'model_digest':'a'*64},{'ollama_model':123},
                  {'data_dir':'\u0000'},{'unknown_secret':'do-not-echo'}]
        for value in values:
            config.write_text(json.dumps(value),encoding='utf-8')
            with self.subTest(value=value), self.assertRaises(deploy.DeploymentError):
                self.settings('--config',str(config))
        for raw in (b'{"port":0,"port":1}',b'{"port":NaN}',b'[]',b'x'*17000):
            config.write_bytes(raw)
            with self.assertRaises(deploy.DeploymentError): self.settings('--config',str(config))
        with self.assertRaises(deploy.DeploymentError): self.settings('--config',str(self.root/'missing'))

    def test_doctor_probes_without_changing_existing_case_files_or_emitting_private_context(self):
        self.data.mkdir(); case = self.data/'cases.sqlite'; case.write_bytes(b'untouched private bytes')
        settings = self.settings('--data-dir',str(self.data),'--ollama-model','PRIVATE_MODEL_NAME')
        with patch.dict(os.environ,{'PRIVATE_API_KEY':'PRIVATE_SECRET'}), patch('platform.node',side_effect=AssertionError('No host collection')):
            result = deploy.doctor(settings)
        text = json.dumps(result)
        self.assertEqual(result['status'],'passed'); self.assertEqual(case.read_bytes(),b'untouched private bytes')
        self.assertEqual(list(self.data.iterdir()),[case])
        for secret in (str(self.data),'PRIVATE_MODEL_NAME','PRIVATE_SECRET','untouched private bytes'):
            self.assertNotIn(secret,text)
        self.assertEqual(result['model_connection'],'not_checked')

    def test_unwritable_directory_and_missing_web_assets_are_reported(self):
        value = self.settings('--data-dir',str(self.data))
        with patch('tempfile.NamedTemporaryFile',side_effect=PermissionError):
            result = deploy.doctor(value)
        self.assertEqual(result['status'],'failed'); self.assertIn('data_directory_not_writable',result['error_codes'])
        result = deploy.doctor(value,root=self.root)
        self.assertFalse(result['checks']['web_assets_present'])

    def test_bundle_and_zip_run_in_chinese_space_path_without_repository(self):
        destination = self.root/'bundle'; archive = self.root/'bundle.zip'
        result = build(destination,zip_path=archive)
        self.assertGreater(result['files'],20)
        extracted = self.root/'解压 with spaces'
        with zipfile.ZipFile(archive) as zipped: zipped.extractall(extracted)
        self.assertFalse((extracted/'.git').exists()); self.assertFalse((extracted/'requirements.txt').exists())
        doctor = self.run_entry(extracted,'--doctor','--data-dir',str(self.data))
        self.assertEqual(doctor.returncode,0,doctor.stderr)
        self.assertEqual(json.loads(doctor.stdout)['bundle']['status'],'verified')
        smoke = self.run_entry(extracted,'--smoke-test')
        self.assertEqual(smoke.returncode,0,smoke.stderr)
        self.assertEqual(json.loads(smoke.stdout)['status'],'passed')
        self.assertIn(b'\r\n',(extracted/'start.cmd').read_bytes())
        self.assertNotIn(b'\r\n',(extracted/'start.sh').read_bytes())

    def test_bundle_detects_file_corruption_and_missing_required_entries(self):
        root = self.package(); script = root/'artemis_v3/web/app.js'; original = script.read_bytes()
        script.write_bytes(original+b'changed')
        with self.assertRaises(deploy.DeploymentError): deploy.bundle_integrity(root)
        script.write_bytes(original)
        manifest = root/'bundle-manifest.json'; value = json.loads(manifest.read_bytes())
        value['files'] = [item for item in value['files'] if item['path']!='launch.py']
        manifest.write_text(json.dumps(value),encoding='utf-8')
        with self.assertRaises(deploy.DeploymentError): deploy.bundle_integrity(root)

    def test_manifest_cannot_read_outside_application_or_use_path_aliases(self):
        root = self.package(); manifest=root/'bundle-manifest.json'
        original=json.loads(manifest.read_bytes())
        for name in ('../private.txt','C:/private.txt','a\\private.txt','a//b','./launch.py','/private.txt'):
            value=copy.deepcopy(original); value['files'][0]['path']=name
            manifest.write_text(json.dumps(value),encoding='utf-8')
            with self.subTest(name=name), patch.object(Path,'read_bytes',side_effect=AssertionError('No file should be read')):
                with self.assertRaises(deploy.DeploymentError): deploy.bundle_integrity(root)

    def test_existing_build_targets_are_never_overwritten(self):
        destination=self.root/'existing';destination.mkdir();sentinel=destination/'private.txt';sentinel.write_text('keep')
        with self.assertRaises(FileExistsError):build(destination)
        self.assertEqual(sentinel.read_text(),'keep')
        archive=self.root/'existing.zip';archive.write_bytes(b'keep')
        with self.assertRaises(ValueError):build(self.root/'new',zip_path=archive)
        self.assertEqual(archive.read_bytes(),b'keep');self.assertFalse((self.root/'new').exists())

    def test_packaging_excludes_local_settings_case_data_env_and_logs(self):
        source=self.root/'source'; source.mkdir()
        shutil.copytree(ROOT/'artemis_v3',source/'artemis_v3',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        for name in ROOT_FILES: shutil.copy2(ROOT/name,source/name)
        (source/'tests/fixtures').mkdir(parents=True)
        shutil.copy2(ROOT/'tests/fixtures/cape_summary_synthetic.json',source/'tests/fixtures/cape_summary_synthetic.json')
        secret='private-marker-do-not-package'
        for name in ('artemis.local.json','.env','cases.sqlite','reviews.sqlite','debug.log'):
            (source/name).write_text(secret)
        (source/'reports').mkdir();(source/'reports/customer.json').write_text(secret)
        destination=self.root/'clean';build(destination,source_root=source)
        self.assertFalse(any(secret.encode() in path.read_bytes() for path in destination.rglob('*') if path.is_file()))
        self.assertFalse((destination/'artemis.local.json').exists());self.assertFalse((destination/'reports').exists())

    def test_smoke_uses_only_temporary_stores_and_no_model(self):
        with patch('artemis_v3.semantic.OllamaLocalProvider.generate',side_effect=AssertionError('No model')):
            result=deploy.smoke_test()
        self.assertEqual(result['status'],'passed');self.assertEqual(result['storage'],'temporary_only')
        self.assertFalse(result['model_called']);self.assertFalse(result['sample_executed'])
        self.assertTrue(all(result['checks'].values()))

    def test_live_launcher_serves_local_ui_with_auto_port_and_persistent_store_configuration(self):
        root=self.package()
        child=subprocess.Popen([sys.executable,'-X','utf8',str(root/'launch.py'),'--no-browser','--data-dir',str(self.data)],
            cwd=self.root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
        lines=Queue()
        def read_output():
            for line in child.stdout:lines.put(line)
        thread=Thread(target=read_output,daemon=True);thread.start()
        try:
            origin=None;deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                try:line=lines.get(timeout=1)
                except Empty:
                    if child.poll() is not None:break
                    continue
                if line.startswith('Open: '):origin=line.strip().removeprefix('Open: ');break
            self.assertIsNotNone(origin,'Launcher did not become ready')
            self.assertTrue(origin.startswith('http://127.0.0.1:'))
            port=int(origin.rsplit(':',1)[1]);connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
            connection.request('GET','/');response=connection.getresponse();html=response.read();connection.close()
            self.assertEqual(response.status,200);self.assertIn(b'artemis-token',html)
            self.assertTrue(self.data.exists());self.assertFalse((self.data/'cases.sqlite').exists())
        finally:
            child.terminate();child.wait(timeout=5);thread.join(timeout=2)
            child.stdout.close();child.stderr.close()

    def test_native_start_wrapper_selects_pinned_python_and_preserves_arguments(self):
        root=self.package()
        env=dict(os.environ,ARTEMIS_PYTHON=sys.executable,ARTEMIS_NO_PAUSE='1')
        args=['--doctor','--data-dir',str(self.data)]
        if os.name=='nt':
            invocation='"'+os.environ.get('COMSPEC','cmd.exe')+'" /d /s /c ""'+str(root/'start.cmd')+'" --doctor --data-dir "'+str(self.data)+'""'
        else:
            invocation=['sh',str(root/'start.sh'),*args]
        result=subprocess.run(invocation,cwd=self.root,env=env,capture_output=True,text=True,encoding='utf-8',timeout=20)
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        self.assertEqual(json.loads(result.stdout)['status'],'passed')
        self.assertTrue(self.data.exists())

    def test_config_errors_are_not_echoed_in_machine_readable_feedback(self):
        root=self.package(); config=self.root/'private-settings.json'
        config.write_text('{"PRIVATE_CONFIG_VALUE":"SECRET_NOT_FOR_FEEDBACK"}',encoding='utf-8')
        result=self.run_entry(root,'--doctor','--config',str(config))
        self.assertEqual(result.returncode,2)
        value=json.loads(result.stdout);self.assertEqual(value['status'],'failed')
        self.assertNotIn('SECRET_NOT_FOR_FEEDBACK',result.stdout+result.stderr)
        self.assertNotIn(str(config),result.stdout+result.stderr)


if __name__=='__main__':
    unittest.main()
