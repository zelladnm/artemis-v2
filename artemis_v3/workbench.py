"""Loopback-only, zero-dependency workbench for existing JSON report investigation.

Run with python -m artemis_v3.workbench. Not an internet-facing deployment server.
"""
import argparse
import base64
import binascii
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets

from .cape import MAX_BYTES, parse_cape_report
from .proposals import MAX_PROPOSAL_BYTES, parse_proposal
from .review import list_reviews, record_review
from .ruleset import MAX_RULESET_BYTES, parse_ruleset
from .scoring import assess_signatures

WEB = Path(__file__).parent / 'web'
MAX_HTTP_BYTES = 15 * 1024 * 1024


def _decode(value, limit):
    if not isinstance(value, str) or len(value) > ((limit + 2) // 3) * 4:
        raise ValueError('Input exceeds its size limit or is not base64 text')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError('Invalid base64 file content') from exc
    if len(raw) > limit:
        raise ValueError('Input exceeds its size limit')
    return raw


def investigate_payload(payload):
    """Recompute from exact uploaded bytes for every operation; no shared case state."""
    if not isinstance(payload, dict) or type(payload.get('synthetic', False)) is not bool:
        raise ValueError('Expected an investigation object and boolean synthetic label')
    report = parse_cape_report(_decode(payload.get('report'), MAX_BYTES), synthetic=payload.get('synthetic', False))
    catalog = assessment = packet = None
    result = {'schema_version': 'artemis-workbench/1', 'report': report.as_dict(),
              'rule_assessment': None, 'proposal_review': None,
              'model_status': 'not_configured', 'ruleset_sha256': None, 'ruleset_synthetic': False}
    if payload.get('ruleset') is not None:
        catalog = parse_ruleset(_decode(payload['ruleset'], MAX_RULESET_BYTES))
        assessment = assess_signatures(report, catalog.rules, version=catalog.version)
        result.update(rule_assessment=assessment.as_dict(), ruleset_sha256=catalog.source_sha256,
                      ruleset_synthetic=catalog.synthetic)
    if payload.get('proposal') is not None:
        if catalog is None:
            raise ValueError('Import a ruleset before a proposal')
        packet = parse_proposal(_decode(payload['proposal'], MAX_PROPOSAL_BYTES),
                                report=report, assessment=assessment, ruleset=catalog)
        result['proposal_review'] = packet
    return result, report, catalog, packet


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate request JSON keys')
        result[key] = value
    return result


class WorkbenchServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, port=8765, *, review_db=None):
        self.token = secrets.token_urlsafe(32)
        self.review_db = Path(review_db).resolve() if review_db else None
        super().__init__(('127.0.0.1', port), WorkbenchHandler)
        self.origin = f'http://127.0.0.1:{self.server_port}'


class WorkbenchHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format, *args):
        pass  # no report contents, query strings or reviewer names in request logs

    def _send(self, status, body, mime='application/json; charset=utf-8'):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=True).encode()
        self.send_response(status)
        for key, value in {
            'Content-Type': mime, 'Content-Length': str(len(body)), 'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
            'Cross-Origin-Resource-Policy': 'same-origin',
            'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        }.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _allowed(self, *, api=False):
        if self.headers.get('Host') != self.server.origin.removeprefix('http://'):
            return False
        origin = self.headers.get('Origin')
        if origin is not None and origin != self.server.origin:
            return False
        if self.headers.get('Sec-Fetch-Site') == 'cross-site':
            return False
        supplied = self.headers.get('X-Artemis-Token', '')
        return not api or (supplied.isascii() and secrets.compare_digest(supplied, self.server.token))

    def do_GET(self):
        if not self._allowed(api=self.path.startswith('/api/')):
            return self._send(403, {'error': 'Local origin or request token rejected'})
        assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                  '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                  '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if self.path in assets:
            name, mime = assets[self.path]
            body = (WEB / name).read_bytes()
            if name == 'index.html':
                body = body.replace(b'__ARTEMIS_TOKEN__', self.server.token.encode()).replace(
                    b'__REVIEW_ENABLED__', b'true' if self.server.review_db else b'false')
            return self._send(200, body, mime)
        if self.path == '/api/demo':
            return self._send(200, {'report': base64.b64encode((WEB / 'demo/report.json').read_bytes()).decode(),
                                    'ruleset': base64.b64encode((WEB / 'demo/ruleset.json').read_bytes()).decode(),
                                    'synthetic': True})
        if self.path == '/api/history':
            if not self.server.review_db:
                return self._send(409, {'error': 'Start with --review-db to enable local history'})
            if not self.server.review_db.exists():
                return self._send(200, {'reviews': []})
            try:
                return self._send(200, {'reviews': list_reviews(self.server.review_db)})
            except ValueError as exc:
                return self._send(400, {'error': str(exc)})
        return self._send(404, {'error': 'Not found'})

    def do_POST(self):
        self.close_connection = True
        if not self._allowed(api=True):
            return self._send(403, {'error': 'Local origin or request token rejected'})
        if self.path not in ('/api/analyze', '/api/review'):
            return self._send(404, {'error': 'Not found'})
        lengths = self.headers.get_all('Content-Length', [])
        if (len(lengths) != 1 or len(lengths[0]) > 9 or not lengths[0].isascii() or not lengths[0].isdigit() or
                self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json'):
            return self._send(400, {'error': 'Expected JSON with a single Content-Length'})
        size = int(lengths[0])
        if not 0 < size <= MAX_HTTP_BYTES:
            return self._send(413, {'error': 'Request exceeds the 15 MiB limit'})
        try:
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('Incomplete request body')
            payload = json.loads(raw, object_pairs_hook=_pairs)
            result, report, catalog, packet = investigate_payload(payload)
            if self.path == '/api/review':
                if not self.server.review_db or catalog is None:
                    return self._send(409, {'error': 'Review requires a ruleset and startup --review-db'})
                result['analyst_review'] = record_review(self.server.review_db, report, catalog,
                                                        payload.get('review_request'), proposal_packet=packet)
            return self._send(200, result)
        except (ValueError, RecursionError) as exc:
            return self._send(400, {'error': str(exc) if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError)
                                   else 'Invalid request JSON'})
        except (OSError, TimeoutError):
            return self._send(400, {'error': 'Local input or storage operation failed'})


def main(argv=None):
    parser = argparse.ArgumentParser(description='Artemis v3 local investigation workbench')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--review-db', help='Explicit local SQLite history destination; omit for read-only investigation')
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error('Port must be between 0 and 65535')
    with WorkbenchServer(args.port, review_db=args.review_db) as server:
        print(f'Artemis v3 workbench: {server.origin}', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
