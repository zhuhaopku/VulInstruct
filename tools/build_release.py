#!/usr/bin/env python3
"""Build a deterministic code-and-data ZIP from an explicit reviewed allowlist."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile
import zipfile
from audit_release import audit, inspect_bytes

ROOT = Path(__file__).resolve().parents[1]
OMIT_DIRS = {'.git', '.venv', 'venv', '__pycache__', '.pytest_cache', 'build', 'dist',
             'research-data', 'runs', 'indexes', 'models', 'internal-review', 'private-notes'}


def candidate(path):
    rel = path.relative_to(ROOT)
    return not (any(p in OMIT_DIRS or p.endswith('.egg-info') for p in rel.parts)
        or path.suffix in {'.pyc', '.zip', '.whl', '.tar'} or path.name == '.DS_Store'
        or (path.suffix == '.gz' and rel.parts[0] != 'data')
        or (path.name.startswith('.env') and path.name != '.env.example')
        or (rel.parent == Path('examples') and path.name.startswith('local-')))


def build(output):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('Output already exists; use a new archive path')
    allowed = json.loads((ROOT / 'resources/release-files.json').read_text())['files']
    if len(allowed) != len(set(allowed)):
        raise ValueError('Duplicate allowlist entry')
    found = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file() and candidate(p)}
    if found != set(allowed):
        raise ValueError('Review file allowlist: added=' + str(sorted(found - set(allowed))) + '; missing=' + str(sorted(set(allowed) - found)))
    payloads, budget = [], [0]
    for name in sorted(allowed):
        rel = PurePosixPath(name)
        if rel.is_absolute() or '..' in rel.parts or '\\' in name:
            raise ValueError('Unsafe allowlist path')
        path = ROOT
        for part in rel.parts:
            path = path / part
            if path.is_symlink():
                raise ValueError('Symlink in release')
        raw = path.read_bytes()
        if any(e['findings'] for e in inspect_bytes(name, raw, budget)):
            raise ValueError('Release scan failed for ' + name)
        payloads.append((name, raw))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        path = Path(temporary) / 'source.zip'
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, raw in payloads:
                info = zipfile.ZipInfo('VulInstruct-open-source/' + name, date_time=(2026, 11, 2, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, raw)
        report = audit(path)
        if report['findings']:
            raise ValueError('Final archive failed release scan')
        # Exclusive creation protects an existing artifact from replacement.
        with output.open('xb') as destination, path.open('rb') as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                destination.write(chunk)
    sha = hashlib.sha256(output.read_bytes()).hexdigest()
    return {'files': len(allowed), 'bytes': output.stat().st_size, 'sha256': sha, 'findings': report['findings']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output), indent=2))


if __name__ == '__main__':
    main()
