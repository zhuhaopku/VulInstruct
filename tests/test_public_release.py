import importlib.util
import hashlib
from pathlib import Path

from vulinstruct.cli import main
from vulinstruct.io import rows, read_json, write_json
from vulinstruct.preflight import check_samples

ROOT = Path(__file__).resolve().parents[1]


def tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bundled_benchmark_contains_complete_runtime_inputs():
    samples = list(rows(ROOT / 'data/benchmarks/primevul.jsonl.gz'))
    assert samples and len({s['sample_id'] for s in samples}) == len(samples)
    groups = {}
    for sample in samples:
        groups.setdefault(sample['pair_id'], []).append(sample)
        assert sample['code'].strip() and isinstance(sample['context'], str)
        assert sample['true_label'] == int(sample['code_type'] == 'before')
        assert all(sample['ground_truth'].get(k) for k in ('code_diff', 'cve_description', 'commit_message'))
    assert all({s['code_type'] for s in pair} == {'before', 'after'} and len(pair) == 2
               for pair in groups.values())


def test_preflight_checks_every_sample_and_blocks_before_encoder(tmp_path, monkeypatch):
    from vulinstruct import cli, retrieval
    samples = [dict(s) for s in list(rows(ROOT / 'data/benchmarks/primevul.jsonl.gz'))[:2]]
    class Dates:
        def __init__(self, *args):
            pass
        def get(self, cve):
            return {'published': '2020-01-01T00:00:00Z'}
    assert check_samples(samples, Dates(), {}, True) == []
    samples[-1]['ground_truth_status'] = 'requires_review'
    errors = check_samples(samples, Dates(), {}, True)
    assert len(errors) == 1 and errors[0]['sample_id'] == samples[-1]['sample_id']
    assert check_samples(samples, Dates(), {}, False) == []
    def forbidden_encoder(**kwargs):
        raise AssertionError('Model must not load before invalid data is rejected')
    monkeypatch.setattr(cli, 'NVDIndex', Dates)
    monkeypatch.setattr(retrieval, 'QwenEncoder', forbidden_encoder)
    benchmark, config = tmp_path / 'benchmark.json', tmp_path / 'config.json'
    write_json(benchmark, samples)
    write_json(config, {'nvd_index': 'unused', 'embedding': {}})
    assert main(['run', '--benchmark', str(benchmark), '--config', str(config),
                 '--output', str(tmp_path / 'run')]) == 2


def test_synthetic_pipeline_covers_all_core_stages(tmp_path):
    report = tool('smoke_pipeline').smoke(tmp_path)
    assert report['network_calls'] == 0 and report['resume_reused_all']
    assert set(report['stages']) == {'extract-general-specifications', 'extract-case-analysis', 'understand',
        'keywords', 'score-cases', 'score-specifications', 'score-nvd', 'domain-specifications', 'detect', 'judge'}


def test_external_data_policy_requires_exact_bytes_and_keeps_source_checks():
    scanner = tool('audit_release')
    content = ('Original data: ' + chr(0x4e2d)).encode()
    name = 'data/example.txt'
    scanner.DATA_POLICY = {name: {'sha256': hashlib.sha256(content).hexdigest(),
                                 'verbatim_external_text': True}}
    assert not scanner.inspect_bytes(name, content, [0])[0]['findings']
    assert scanner.inspect_bytes(name, content + b'changed', [0])[0]['findings']
    assert scanner.inspect_bytes('src/example.py', content, [0])[0]['findings']
    credential = b'api_' + b'key = "' + b'A' * 32 + b'"'
    findings = scanner.inspect_bytes(name, content + credential, [0])[0]['findings']
    assert any(f['rule'] == 'credential_assignment' for f in findings)
