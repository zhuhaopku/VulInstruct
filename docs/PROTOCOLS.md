# Evaluation protocols

## Main pipeline

The default `domain-cascade-v4` protocol performs target understanding, general and NVD retrieval, independent applicability scoring, domain-specification generation, detection and root-cause judging. The default top-k is 10 and the three relevance thresholds are 6/6/6. See [Retrieval](RETRIEVAL.md) for candidate selection.

The detector receives repository, filename, target code, available context and selected knowledge. The target label, CVE description, fixing message and paired diff are reserved for evaluation. Target CVE/date metadata is used to filter historical retrieval candidates.

Detection returns one `<has_vulnerability>` value (`yes` or `no`) and a non-empty `<suspected_root_cause>` explanation. Stage 2 prepares the detector reasoning from its root cause and analysis sections, and supplies the reference CVE description, fixing message and paired function diff to the judge.

All detection prompt versions use the `correct-lenient-stage2-v1` judge protocol. Vulnerable samples use `MATCH/MISMATCH`; patched samples use `FALSE_ALARM/CORRECT`, including the patched-code rule for findings on newly added patch lines. See [Evaluation](EVALUATION.md) for the exact decision table, rationale preparation and label meanings.

## Sample and pair validation

Evaluation uses unique `sample_id` values and explicit `pair_id` values. Every pair contains one `before` sample with label 1 and one `after` sample with label 0. Results must cover the benchmark and match its sample identities, sides and labels. Versioned outputs are checked against input hashes and parsed answers where available.

Missing/duplicate samples, incomplete pairs, request failures and invalid positive-detection judgments prevent aggregate evaluation. `--binary-only` evaluates detector labels without a judge and returns binary metrics only.

## Metrics

Binary metrics use the detector's label. For CORRECT Lenient metrics, a positive prediction has effective label 1 when its judge returns `MATCH` on a vulnerable sample or `FALSE_ALARM` on a patched sample. `MISMATCH` on a vulnerable sample and `CORRECT` on a patched sample have effective label 0. A negative detector prediction also has effective label 0 and skips judging. Labels belonging to the wrong sample side are invalid.

| Metric | Formula |
|---|---|
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 | 2TP / (2TP + FP + FN) |
| Accuracy | (TP + TN) / sample count |

Zero-denominator precision, recall and F1 are defined as zero. Both metric sets are reported with confusion matrices.

| Pair category | Before prediction | After prediction |
|---|---:|---:|
| P-C | 1 | 0 |
| P-V | 1 | 1 |
| P-B | 0 | 0 |
| P-R | 0 | 1 |

Pair rates use the number of complete function pairs. VP-S = (P-C count - P-R count) / pair count. Pair metrics are reported separately for binary and mechanism-matching predictions.

## Model settings and recovery

`examples/deepseek-flash.json` configures the Flash model alias for knowledge, detection and judging. Knowledge stages disable thinking; detection and judging enable it. Stage-specific output budgets and request options are explicit in the configuration.

The transport retries declared transient HTTP/network failures within the request budget. Missing or truncated final text can use the configured larger-budget, low-effort and direct-output recovery stages. Each stage uses the same prompt/evidence and records its identity. Completed valid answers are reused. Recovery is triggered by output completeness and schema validation.

Applicability-score repairs retain the original reported identity and require an unambiguous mapping to supplied candidates. Domain-specification repairs use the same evidence and reject unsupported references. Repair attempts are bounded and recorded.

## Evaluate a completed run

```sh
python -m vulinstruct evaluate --results runs/primevul-flash/results.json --benchmark data/benchmarks/primevul.jsonl.gz --output runs/primevul-flash/verified-metrics.json
```

Evaluation checks the saved model responses and benchmark coverage without new model calls. The result identifies the metric protocol. Use `--binary-only` for detections produced with `run --no-judge`.

The configurable prompt protocols are `corrected-v1`, `domain-cascade-v2`, `domain-cascade-v3` and `domain-cascade-v4`. The documented workflow uses `domain-cascade-v4`.

## Evidence conditions and provenance

PrimeVul judging uses the supplied CVE evidence, fixing message and exact paired function diff. For SVEN's patch/CWE evidence, set an explicit `before` cutoff and `allow_patch_only_judge: true`; results record `ground_truth_status: patch_only`. Records marked `requires_review` must have their evidence resolved before fresh judging.

Saved results identify the sample, pipeline, implementation, detection prompt protocol and judge protocol/model. Positive results also retain the exact prepared judge input, prompt and answer. Request caches identify the model, endpoint hash inputs and complete request body. Local caches contain final text and usage.
