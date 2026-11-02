import gzip
import io
import json
import zipfile
import pytest
from test_public_release import tool


def test_nested_archive_scans_decoded_text_without_echoing_secrets(tmp_path):
    secret = 'sk-' + 'A' * 30
    compressed = gzip.compress(json.dumps({'value': secret, 'text': chr(0x4e2d)}).encode())
    archive = tmp_path / 'nested.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('nested.json.gz', compressed)
    report = tool('audit_release').audit(archive)
    assert report['findings'] >= 1
    assert secret not in json.dumps(report)
    rules = {f['rule'] for row in report['inventory'] for f in row['findings']}
    assert {'provider_token', 'escaped_cjk'} <= rules


def test_scanner_rejects_runtime_files_and_plaintext_cjk(tmp_path):
    (tmp_path / '.env').write_text('EXAMPLE=value')
    (tmp_path / 'comment.py').write_text('# ' + chr(0x4e2d))
    report = tool('audit_release').audit(tmp_path)
    rules = {f['rule'] for row in report['inventory'] for f in row['findings']}
    assert {'cjk', 'environment_file'} <= rules


def test_duplicate_zip_member_fails(tmp_path):
    archive = tmp_path / 'duplicate.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('one.txt', 'first')
        with pytest.warns(UserWarning):
            z.writestr('one.txt', 'second')
    with pytest.raises(ValueError, match='Duplicate'):
        tool('audit_release').audit(archive)
