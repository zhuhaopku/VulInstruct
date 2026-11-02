#!/usr/bin/env python3
"""Inventory every release file and fail on release hygiene findings.

Scan a clean source directory or ZIP, including nested ZIP/gzip contents. Findings
contain rule names and line numbers, never matching secret values. This is a
bounded static scan, not a credential-validity check or a Git-history audit.
"""
import argparse
import bisect
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
POLICY_PATH = Path(__file__).resolve().parents[1] / 'resources/data-scan-policy.json'
DATA_POLICY = json.loads(POLICY_PATH.read_text())['files'] if POLICY_PATH.exists() else {}
RULES = {
    'cjk': re.compile(r'[\u3400-\u9fff\uf900-\ufaff\U00020000-\U0002fa1f]'),
    'private_key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'provider_token': re.compile(r'\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{20,})\b'),
    'credential_assignment': re.compile(r'''(?i)["']?(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)["']?\s*[:=]\s*["'][A-Za-z0-9_+/.=-]{16,}["']'''),
    'url_userinfo': re.compile(r'https?://[^\s/"\']+@[^\s/"\']+'),
    'private_path': re.compile(r'/(?:Users|home)/[A-Za-z0-9_.-]+/|[A-Z]:\\Users\\[^\\]+\\'),
    'private_ipv4': re.compile(r'\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b'),
}
FORBIDDEN_PARTS = {'.git', '.env', '.venv', 'venv', '__pycache__', '.pytest_cache', '.DS_Store',
                   'research-data', 'runs', 'indexes', 'node_modules', '.ssh', '.aws'}
FORBIDDEN_SUFFIXES = {'.pem', '.key', '.p12', '.pfx', '.sqlite', '.db', '.pyc', '.pkl', '.pickle'}
# These exact invalid URL fixtures exercise rejection before any request is sent.
ALLOWED = {
    ('tests/test_release_hardening.py', 'url_userinfo'): {
        'http://localhost:80@external.invalid', 'https://user:pass@example.invalid'},
    ('tools/audit_release.py', 'url_userinfo'): {
        'http://localhost:80@external.invalid', 'https://user:pass@example.invalid'},
}


def normalized_name(name):
    parts = PurePosixPath(name).parts
    # ZIP delivery has one package directory; strip only that known prefix.
    if parts and parts[0] == 'VulInstruct-open-source':
        parts = parts[1:]
    return '/'.join(parts)


def inspect_bytes(name, raw, budget, depth=0):
    if depth > 4 or len(raw) > MAX_FILE:
        raise ValueError('Archive depth or file-size limit exceeded')
    budget[0] += len(raw)
    if budget[0] > MAX_TOTAL:
        raise ValueError('Scan byte limit exceeded')
    name = normalized_name(name)
    entry = {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'findings': [], 'accepted_fixtures': []}
    policy = DATA_POLICY.get(name, {})
    if policy.get('sha256') != entry['sha256']:
        policy = {}
    parts = PurePosixPath(name).parts
    if name.startswith('/') or '..' in parts or '\\' in name:
        entry['findings'].append({'rule': 'unsafe_path'})
    if any(p in FORBIDDEN_PARTS or p.endswith('.egg-info') for p in parts) or Path(name).suffix in FORBIDDEN_SUFFIXES:
        entry['findings'].append({'rule': 'forbidden_artifact'})
    if any(p.startswith('.env') and p != '.env.example' for p in parts):
        entry['findings'].append({'rule': 'environment_file'})
    entries = [entry]
    if raw[:2] == b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            decoded = stream.read(MAX_FILE + 1)
        entries.extend(inspect_bytes(name + '!decoded', decoded, budget, depth + 1))
        return entries
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            seen = set()
            for member in archive.infolist():
                if member.filename in seen:
                    raise ValueError('Duplicate archive member')
                seen.add(member.filename)
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError('Symlink in archive')
                if member.is_dir():
                    continue
                if member.file_size > MAX_FILE:
                    raise ValueError('Archive member too large')
                entries.extend(inspect_bytes(name + '!' + member.filename, archive.read(member), budget, depth + 1))
        return entries
    try:
        content = raw.decode('utf-8')
    except UnicodeDecodeError:
        if policy.get('numeric_array'):
            entry['accepted_fixtures'].append({'rule': 'pinned_numeric_array'})
        else:
            entry['findings'].append({'rule': 'unreviewed_binary'})
        return entries
    line_starts = [m.start() for m in re.finditer('\n', content)]
    for rule, pattern in RULES.items():
        for match in pattern.finditer(content):
            finding = {'rule': rule, 'line': bisect.bisect_left(line_starts, match.start()) + 1}
            match_hash = hashlib.sha256(match.group().encode()).hexdigest()
            external_match = (rule == 'cjk' and policy.get('verbatim_external_text')) or match_hash in policy.get('allowed_matches', {}).get(rule, [])
            if match.group() in ALLOWED.get((name, rule), set()) or external_match:
                entry['accepted_fixtures'].append(finding)
            else:
                entry['findings'].append(finding)
    # JSON may encode non-English strings with ASCII escape sequences.
    if name.replace('!decoded', '').removesuffix('.gz').endswith('.json'):
        def visit(value):
            if isinstance(value, str):
                return bool(RULES['cjk'].search(value))
            if isinstance(value, list):
                return any(visit(v) for v in value)
            if isinstance(value, dict):
                return any(visit(k) or visit(v) for k, v in value.items())
            return False
        try:
            if visit(json.loads(content)) and not policy.get('verbatim_external_text') and not any(f['rule'] == 'cjk' for f in entry['findings']):
                entry['findings'].append({'rule': 'escaped_cjk'})
        except json.JSONDecodeError:
            entry['findings'].append({'rule': 'invalid_json'})
    return entries


def audit(path):
    path, budget, entries = Path(path), [0], []
    if path.is_symlink():
        raise ValueError('Release root must not be a symlink')
    if path.is_dir():
        for file in sorted(path.rglob('*')):
            if file.is_symlink():
                raise ValueError('Release contains a symlink')
            if file.is_file():
                if file.stat().st_size > MAX_FILE:
                    raise ValueError('Release file too large')
                entries.extend(inspect_bytes(file.relative_to(path).as_posix(), file.read_bytes(), budget))
    else:
        with zipfile.ZipFile(path) as archive:
            seen = set()
            for member in archive.infolist():
                if member.filename in seen:
                    raise ValueError('Duplicate archive member')
                seen.add(member.filename)
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError('Symlink in archive')
                if not member.is_dir():
                    if member.file_size > MAX_FILE:
                        raise ValueError('Archive member too large')
                    entries.extend(inspect_bytes(member.filename, archive.read(member), budget))
    return {'schema': 'release-audit-v1', 'files': len(entries), 'scanned_bytes': budget[0],
            'findings': sum(len(e['findings']) for e in entries),
            'accepted_fixture_matches': sum(len(e['accepted_fixtures']) for e in entries), 'inventory': entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--output', type=Path, help='Write outside the scanned release tree')
    args = parser.parse_args()
    report = audit(args.path)
    if args.output:
        if args.path.is_dir() and args.path.resolve() in args.output.resolve().parents:
            parser.error('Write the audit outside the scanned tree to avoid self-referential manifests')
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'inventory'}, indent=2))
    for row in report['inventory']:
        if row['findings']:
            print(json.dumps({'path': row['path'], 'findings': row['findings']}))
    raise SystemExit(1 if report['findings'] else 0)


if __name__ == '__main__':
    main()
