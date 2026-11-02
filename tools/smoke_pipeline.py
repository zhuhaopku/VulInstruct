#!/usr/bin/env python3
"""Exercise real extraction, indexes, retrieval, AS, detection and evaluation.

Model replies and embeddings are deterministic synthetic fixtures. This checks
pipeline wiring; its scores say nothing about real vulnerability detection.
No network, model download, credentials, GPU, or research data is needed.
"""
import argparse
import json
from pathlib import Path
import tempfile
import numpy as np
from vulinstruct.evaluation import evaluate
from vulinstruct.io import read_json, write_json, write_rows
from vulinstruct.knowledge import build_knowledge
from vulinstruct.nvd import build_index, NVDIndex
from vulinstruct.pipeline import Pipeline
from vulinstruct.retrieval import build_dense, DenseIndex


class SyntheticEncoder:
    identity = {'model': 'synthetic-fixture', 'revision': '1'}

    def encode(self, texts):
        return np.asarray([[len(t) + 1, sum(map(ord, t)) % 17 + 1] for t in texts], dtype=float)


class SyntheticClient:
    def __init__(self):
        self.stages = []

    def ask(self, prompt, model, stage):
        self.stages.append(stage)
        if stage == 'extract-general-specifications':
            return '<understand>Synthetic packet parser.</understand><spec>HS-BOUNDS-001: Check the destination capacity.</spec>'
        if stage == 'extract-case-analysis':
            return '<model>Untrusted packet</model><vuln>Unchecked copy</vuln><solution>Check capacity before copying</solution>'
        if stage == 'understand':
            return '<understand>Synthetic widget packet parser.</understand>'
        if stage == 'keywords':
            return json.dumps({'products': ['synthetic_widget'], 'identifiers': ['parse.c'], 'domain_terms': ['packet']})
        if stage.startswith('score-'):
            candidates = json.loads(prompt.split('CANDIDATES:\n')[1])
            return json.dumps({'scores': [{'id': r['id'], 'score': 8, 'reason': 'Synthetic fixture'} for r in candidates]})
        if stage == 'domain-specifications':
            return json.dumps({'specifications': [{'id': 'AS-DOMAIN-001', 'statement': 'Check capacity before copying.',
                'attack_pattern': 'Unchecked copy', 'supporting_cves': ['CVE-1999-900001', 'CVE-1999-900002']}]})
        if stage == 'detect':
            target, _ = json.JSONDecoder().raw_decode(prompt.split('TARGET:\n', 1)[1])
            label = 'no' if 'if (n > 4)' in target['code'] else 'yes'
            return f'<has_vulnerability>{label}</has_vulnerability><suspected_root_cause>Synthetic capacity-check fixture.</suspected_root_cause>'
        if stage == 'judge':
            return '<match_result>MATCH</match_result>'
        raise AssertionError('Unexpected synthetic stage: ' + stage)


def smoke(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    before = 'void parse(char *s, size_t n) { char b[4]; memcpy(b, s, n); }'
    after = 'void parse(char *s, size_t n) { char b[4]; if (n > 4) return; memcpy(b, s, n); }'
    client, encoder = SyntheticClient(), SyntheticEncoder()
    raw = [dict(cve_id=f'CVE-1999-{i}', commit_hash='synthetic' + str(i), repository='synthetic_widget',
        commit_msg='Check capacity', cve_desc='Synthetic unchecked packet copy', cwe_list=['CWE-120'],
        vulnerableMethods_before=[{'raw_code': before}], vulnerableMethods_after=[{'raw_code': after}]) for i in (900001, 900002)]
    write_json(output / 'correct.json', raw)
    extraction = build_knowledge(output / 'correct.json', output / 'knowledge.json', client, 'synthetic')
    corpus = read_json(output / 'knowledge.json')
    for row in corpus:
        row['published'] = '1999-01-01'
    write_json(output / 'knowledge.json', corpus)
    build_dense(output / 'knowledge.json', output / 'dense', encoder)
    write_rows(output / 'nvd.jsonl', [dict(cve_id=r['cve_id'], published='1999-01-01', modified=None,
        description='synthetic_widget parse.c unchecked packet copy', cpes=[], cwes=[], references=[]) for r in raw])
    build_index(output / 'nvd.jsonl', output / 'nvd.sqlite')
    samples = [dict(sample_id='synthetic-' + side, pair_id='synthetic-pair', code_type=side, true_label=int(side == 'before'),
        cve_id='CVE-2020-900003', published='2020-01-01', repository='synthetic_widget', filename='parse.c',
        code=code, context='', ground_truth_status='source_pair',
        ground_truth={'cve_description': 'Synthetic unchecked packet copy', 'commit_message': 'Check capacity', 'code_diff': '- memcpy\n+ if (n > 4) return; memcpy'})
        for side, code in [('before', before), ('after', after)]]
    write_json(output / 'benchmark.json', samples)
    config = {'models': {'knowledge': 'synthetic', 'detector': 'synthetic', 'judge': 'synthetic'},
              'prompt_protocol': 'domain-cascade-v4', 'sample_workers': 1, 'score_workers': 1}
    pipeline = Pipeline(client, DenseIndex(output / 'dense', encoder), NVDIndex(output / 'nvd.sqlite'), config)
    results = pipeline.run(samples, output / 'run')
    metrics = evaluate(results, [s['sample_id'] for s in samples])
    assert extraction['successful'] == 2 and not extraction['failed']
    assert all(len(r['knowledge']['nvd']) == 2 and r['knowledge']['domain_specifications'] for r in results)
    assert metrics['binary']['confusion_matrix'] == {'tp': 1, 'fp': 0, 'tn': 1, 'fn': 0}
    calls = len(client.stages)
    assert pipeline.run(samples, output / 'run') == results and len(client.stages) == calls
    report = {'kind': 'synthetic-wiring-only', 'extraction': extraction, 'stages': sorted(set(client.stages)),
              'mock_model_calls': calls, 'network_calls': 0, 'resume_reused_all': True, 'metrics': metrics}
    write_json(output / 'smoke-report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New directory; omit to use a temporary directory')
    args = parser.parse_args()
    if args.output:
        if args.output.exists():
            parser.error('Choose a new output directory')
        report = smoke(args.output)
    else:
        with tempfile.TemporaryDirectory() as directory:
            report = smoke(directory)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
