#!/usr/bin/env python3
"""Freeze a complete-pair development sample before making new model calls."""
import argparse
import hashlib
import json
import random
from pathlib import Path
from vulinstruct.io import rows, write_rows, write_json, file_digest, digest
from vulinstruct.evaluation import evaluate

p=argparse.ArgumentParser()
p.add_argument('--source',required=True)
p.add_argument('--output',required=True)
p.add_argument('--pairs',type=int,default=50)
p.add_argument('--seed',type=int,default=20261101)
a=p.parse_args()
if Path(a.output).exists():raise SystemExit('Choose a new output; frozen benchmarks are not overwritten')
samples=list(rows(a.source));evaluate([dict(s,prediction=0,status='ok') for s in samples],require_judge=False)
chosen=set(random.Random(a.seed).sample(sorted({s['pair_id'] for s in samples}),a.pairs))
selected=[s for s in samples if s['pair_id'] in chosen];write_rows(a.output,selected)
write_json(a.output+'.manifest.json',dict(protocol='fixed-random-complete-pairs-v1',seed=a.seed,
    n_pairs=a.pairs,n_samples=len(selected),source_sha256=file_digest(a.source),benchmark_sha256=file_digest(a.output),
    records_sha256=digest(selected),sample_ids=[s['sample_id'] for s in selected],
    selection_note='Uniform random complete pairs; development pilot, not a protected holdout.'))
print(json.dumps(dict(samples=len(selected),pairs=a.pairs,records_sha256=digest(selected))))
