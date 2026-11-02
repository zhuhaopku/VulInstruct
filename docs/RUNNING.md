# Running the main evaluation

All commands run from the extracted repository root. The PrimeVul benchmark is `data/benchmarks/primevul.jsonl.gz`. The inputs are already included.

## Installation and offline checks

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test,embedding]'
python -m vulinstruct doctor
python -m pytest -q
python tools/smoke_pipeline.py
```

Evaluation uses the Python standard library. Preflight and tests use NumPy. Fresh dense retrieval also needs PyTorch/Transformers and Qwen3-Embedding-0.6B. GPU execution is recommended for embedding speed; CPU execution is supported. `requirements-embedding-tested.txt` records a tested Linux environment; choose a PyTorch wheel for your hardware.

## Retrieval inputs

The general vectors are ready to use. Build the NVD SQLite index once from the included corpus:

```sh
python -m vulinstruct index-nvd --corpus data/knowledge/nvd-2002-2024.jsonl.gz --output indexes/nvd.sqlite
```

This local command requires no NVD API key, network request or GPU. Allow approximately 1 GB of free space for the generated index. An existing output is protected; reuse a matching index or choose another path and update your local configuration.

The general index uses Qwen revision `c54f2e6e80b2d7b7de06f51cec4959f6b3e03418`, max length 8192 and last-token/L2 pooling. Keep the configured query encoder consistent with the index. Changing the encoder or feature representation requires rebuilding vectors.

## Model service

```sh
cp examples/deepseek-flash.json examples/local-flash.json
```

Edit `base_url` to your HTTPS OpenAI-compatible chat-completions endpoint and each `models` value to an alias your service supports. `deepseek-flash` is a configurable service alias. Verify the service supports the configured `thinking` and `reasoning_effort` request options. Supply `VULINSTRUCT_API_KEY` in the launching process environment; never place credentials in JSON or URLs. Local configuration files and runtime outputs are ignored by Git.

File paths resolve relative to the configuration file. The template points directly to bundled `data/` files and the generated `indexes/nvd.sqlite`. It uses four sample workers and three relevance-scoring workers. Lower worker counts for services with stricter rate limits.

## Check and run PrimeVul

```sh
python -m vulinstruct preflight --benchmark data/benchmarks/primevul.jsonl.gz --config examples/local-flash.json --output runs/primevul-preflight.json
python -m vulinstruct run --benchmark data/benchmarks/primevul.jsonl.gz --config examples/local-flash.json --output runs/primevul-flash --max-calls 15000
python -m vulinstruct evaluate --results runs/primevul-flash/results.json --benchmark data/benchmarks/primevul.jsonl.gz --output runs/primevul-flash/verified-metrics.json
```

Preflight validates all sample identities, pairs, function code, temporal cutoffs, judge evidence, vector checksums and encoder identity. It reports credential presence but does not test the endpoint or download model weights. `run` also validates every selected sample's evidence and dates before loading model weights or making LLM calls.

Without `--pairs`, `run` processes the entire benchmark. For an optional service check, add `--pairs 1` and use a separate output directory; do not report that check as the main experiment.

The main flow performs understanding, keyword extraction, general/NVD retrieval, relevance scoring, domain-specification generation when enough NVD cases qualify, detection and root-cause judging. The template selects `domain-cascade-v4`. All three model roles can use the same Flash service.

`--max-calls` limits actual network requests in this invocation, including retries. The cap is shared across workers and does not reset the response cache. It does not limit tokens or currency. The example cap permits a full run but does not guarantee completion within that budget; actual usage depends on retrieval and response recovery.

## Outputs and resume

The output directory records `benchmark-selection.json`, per-sample results, `progress.json`, `results.json`, and `metrics.json` after successful completion. Traces include retrieval candidates, relevance judgments, selected evidence and final model answers. Successful results carry input and pipeline hashes.

If any sample fails, no aggregate F1 is produced. Inspect the sample errors and resume with the same configuration and output directory:

```sh
python -m vulinstruct run --benchmark data/benchmarks/primevul.jsonl.gz --config examples/local-flash.json --output runs/primevul-flash --max-calls 15000 --retry-errors
```

Successful samples are reused. Each invocation has a new request cap. `--refresh-api-cache` requests fresh responses for retried or missing samples; use a new output directory for a wholly fresh experiment. A changed input or pipeline is not silently mixed into a previous run.

`--no-judge` explicitly requests binary-only evaluation; pass `--binary-only` to `evaluate` for those results.

Main evaluation uses CORRECT Lenient Mode. Read `correct_lenient` in the metric output for rationale-based scores; `binary` reports labels alone. The judge uses separate before/after prompts and records its exact input and response. See [Evaluation](EVALUATION.md) for the decision table and label definitions. `evaluate` checks saved results and does not perform new judge calls.

## Common failures

| Symptom | Action |
|---|---|
| Missing API key | Set the named environment variable in the process launching the CLI. |
| HTTP redirect | Configure the service's final HTTPS endpoint. |
| Unknown model or request option | Use aliases and options supported by your provider. |
| Missing NVD index | Run the local `index-nvd` command above. |
| Encoder identity mismatch | Match the bundled encoder configuration or build a new index. |
| Request cap exhausted | Review usage and resume with an explicit new cap. |
| Truncated response | Inspect the configured recovery budgets and recorded error. |
| Data checksum mismatch | Restore the affected file from the same release archive. |
