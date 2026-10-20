"""Browser-test fixture using a fake Ollama HTTP service; never production wiring."""
import argparse
from pathlib import Path
import sys
from threading import Thread
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artemis_v3.semantic import OllamaLocalProvider
from artemis_v3.workbench import WorkbenchServer
from test_v3_semantic import FakeOllama, ThreadingHTTPServer

parser = argparse.ArgumentParser()
parser.add_argument('--review-db', required=True)
parser.add_argument('--case-db')
args = parser.parse_args()
with ThreadingHTTPServer(('127.0.0.1', 0), FakeOllama) as ollama:
    ollama.mode, ollama.requests = 'adjustment', []
    thread = Thread(target=ollama.serve_forever, daemon=True); thread.start()
    with WorkbenchServer(0, review_db=args.review_db, case_db=args.case_db,
                         semantic_provider=OllamaLocalProvider('test', port=ollama.server_port)) as workbench:
        print(workbench.origin, flush=True)
        try:
            workbench.serve_forever()
        finally:
            ollama.shutdown(); thread.join()
