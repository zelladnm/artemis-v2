"""Build an application-only field-test folder/ZIP without local settings or case data."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = ('launch.py', 'start.cmd', 'start.sh', 'doctor.cmd', 'doctor.sh',
              'FIRST_TEST.md', 'settings.example.json', 'SOURCE_BASELINE.json')
WEB_FILES = ('index.html', 'app.js', 'style.css', 'demo/report.json', 'demo/ruleset.json')


def build(output_dir, *, source_root=ROOT, zip_path=None):
    source_root = Path(source_root).resolve()
    if Path(output_dir).is_symlink() or (zip_path is not None and Path(zip_path).is_symlink()):
        raise ValueError('Build destinations cannot be symlinks')
    destination = Path(output_dir).resolve()
    archive_path = Path(zip_path).resolve() if zip_path is not None else None
    if destination.is_relative_to(source_root / 'artemis_v3'):
        raise ValueError('Build output cannot be inside the application package')
    if archive_path is not None and (archive_path.exists() or archive_path.is_relative_to(destination)):
        raise ValueError('ZIP must be a new path outside the output folder')
    sources = {name: source_root / name for name in ROOT_FILES}
    sources['README.md'] = source_root / 'FIRST_TEST.md'
    sources['examples/report_synthetic.json'] = source_root / 'tests/fixtures/cape_summary_synthetic.json'
    for path in sorted((source_root / 'artemis_v3').rglob('*.py')):
        sources[path.relative_to(source_root).as_posix()] = path
    for name in WEB_FILES:
        sources['artemis_v3/web/' + name] = source_root / 'artemis_v3/web' / name
    for path in sorted((source_root / 'docs/v3').glob('*.md')):
        sources[path.relative_to(source_root).as_posix()] = path
    payloads = {}
    for name, path in sources.items():
        if path.is_symlink() or not path.resolve().is_relative_to(source_root) or not path.is_file():
            raise ValueError('A required application source is missing or is a symlink')
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('Application source exceeds the file size limit')
        raw = path.read_bytes().replace(b'\r\n', b'\n')
        if name.endswith('.cmd'):
            raw = raw.replace(b'\n', b'\r\n')
        payloads[name] = raw
    if not 1 <= len(payloads) <= 256 or sum(map(len, payloads.values())) > 32 * 1024 * 1024:
        raise ValueError('Application bundle exceeds its file/byte budget')
    manifest = {'schema_version': 'artemis-field-bundle/1', 'files': [
        {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        for name, raw in sorted(payloads.items())]}
    payloads['bundle-manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    if len(payloads['bundle-manifest.json']) > 64 * 1024:
        raise ValueError('Bundle manifest exceeds its size limit')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o700, exist_ok=False)  # Never overwrite an existing test package.
    for name, raw in payloads.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as target:
            target.write(raw)
        if path.suffix == '.sh':
            path.chmod(0o755)
    if archive_path is not None:
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(payloads):
                archive.write(destination / name, name)
    return {'schema_version': 'artemis-field-build/1', 'files': len(payloads),
            'bytes': sum(map(len, payloads.values())), 'manifest_sha256': hashlib.sha256(payloads['bundle-manifest.json']).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, help='New application folder; existing paths are refused')
    parser.add_argument('--zip', dest='zip_path', help='Optional new ZIP path outside the output folder')
    args = parser.parse_args(argv)
    try:
        result = build(args.output_dir, zip_path=args.zip_path)
    except (OSError, ValueError):
        parser.exit(2, 'Build failed. Check source files and choose new output paths.\n')
    print(json.dumps(result, indent=2)); return 0


if __name__ == '__main__':
    raise SystemExit(main())
