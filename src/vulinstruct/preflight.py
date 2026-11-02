"""Validate a complete benchmark and its retrieval inputs without model calls."""
import os
from collections import Counter
from pathlib import Path

from .evaluation import evaluate
from .io import file_digest, read_json, rows
from .nvd import NVDIndex, timestamp


def load_config(path):
    path = Path(path).resolve()
    config = read_json(path)
    for key in ('general_index', 'nvd_index', 'publication_metadata', 'cache_dir'):
        if config.get(key) and not Path(config[key]).is_absolute():
            config[key] = str((path.parent / config[key]).resolve())
    return config


def select_samples(benchmark, pairs=None):
    samples = list(rows(benchmark))
    if pairs is not None:
        if pairs < 1:
            raise ValueError('pairs must be positive')
        chosen = set(list(dict.fromkeys(s['pair_id'] for s in samples))[:pairs])
        samples = [s for s in samples if s['pair_id'] in chosen]
    evaluate([dict(s, prediction=0, status='ok') for s in samples], require_judge=False)
    return samples


def check_samples(samples, nvd, config, include_judge=True):
    """Use the same evidence and date requirements as Pipeline.run_sample."""
    errors = []
    for sample in samples:
        reasons = []
        if not isinstance(sample.get('code'), str) or not sample['code'].strip():
            reasons.append('empty_function')
        cutoff = sample.get('published') or config.get('before')
        if not cutoff and sample.get('cve_id'):
            metadata = nvd.get(sample['cve_id'])
            cutoff = metadata.get('published') if metadata else None
        try:
            timestamp(cutoff)
        except (TypeError, ValueError):
            reasons.append('missing_or_invalid_cutoff')
        if include_judge:
            if sample.get('ground_truth_status') == 'requires_review':
                reasons.append('conflicting_source_metadata')
            if sample.get('ground_truth_status') == 'patch_only' and not config.get('allow_patch_only_judge', False):
                reasons.append('patch_only_judging_not_enabled')
            truth = sample.get('ground_truth', {})
            if not all(truth.get(k) for k in ('cve_description', 'commit_message', 'code_diff')):
                reasons.append('incomplete_judge_evidence')
        if reasons:
            errors.append({'sample_id': sample['sample_id'], 'reasons': reasons})
    return errors


def preflight(benchmark, config_path, include_judge=True, pairs=None):
    from .retrieval import DenseIndex

    config = load_config(config_path)
    samples = select_samples(benchmark, pairs)
    embedding = config.get('embedding', {})

    class IdentityOnlyEncoder:
        identity = {'model': embedding.get('model', 'Qwen/Qwen3-Embedding-0.6B'),
                    'revision': embedding.get('revision'), 'pooling': 'last-token/l2',
                    'max_length': embedding.get('max_length', 8192), 'instruction': None}

        def encode(self, texts):
            raise RuntimeError('Preflight must not encode text')

    # Verifies hashes, numeric vectors, case alignment and configured encoder.
    dense = DenseIndex(config['general_index'], IdentityOnlyEncoder())
    nvd = NVDIndex(config['nvd_index'], config.get('publication_metadata'))
    try:
        errors = check_samples(samples, nvd, config, include_judge)
        return {'data_ready': not errors, 'samples': len(samples),
                'pairs': len({s['pair_id'] for s in samples}),
                'labels': dict(Counter(str(s['true_label']) for s in samples)),
                'judge_enabled': include_judge, 'benchmark_sha256': file_digest(benchmark),
                'general_cases': len(dense.corpus), 'nvd_records': nvd.manifest['count'],
                'api_key_present': bool(os.environ.get(config.get('key_env', 'VULINSTRUCT_API_KEY'))),
                'network_calls': 0, 'model_weights_loaded': False, 'errors': errors}
    finally:
        nvd.close()
