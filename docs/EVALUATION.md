# Evaluation

VulInstruct adopts the evaluation framework introduced by [CORRECT](https://arxiv.org/abs/2504.13474), using the **Lenient Mode** described in [Appendix A of the VulInstruct paper](https://arxiv.org/html/2511.04014v2#A1). A positive label alone is insufficient: the detector's explanation is evaluated against the reference vulnerability. The judge protocol is `correct-lenient-stage2-v1`.

## Detection and judging

1. The detector analyzes the target function, available context and retrieved knowledge. It returns one `yes` or `no` assessment and a root-cause explanation.
2. A `no` prediction skips the judge. It is a false negative for a vulnerable function and a true negative for a patched function.
3. A `yes` prediction invokes the Stage 2 judge with the CVE description, fixing commit message, paired function diff and the detector's prepared reasoning. The judge uses separate prompts for vulnerable (`before`) and patched (`after`) functions.
4. The evaluator combines the sample's true label, detector prediction and judge conclusion using the table below.

Reference descriptions, fixing messages, diffs and the sample's before/after identity are used by evaluation. They are not supplied to the detector. Target CVE/date metadata is used separately to filter historical retrieval candidates.

## Lenient decision table

| Actual code | Detector prediction | Rationale judgment | Outcome |
|---|---|---|---|
| Vulnerable | Vulnerable | Identifies the original vulnerability | TP |
| Vulnerable | Vulnerable | Reports unrelated issues only | FN |
| Vulnerable | Non-vulnerable | Judge not needed | FN |
| Patched | Non-vulnerable | Judge not needed | TN |
| Patched | Vulnerable | Still claims the original vulnerability exists | FP |
| Patched | Vulnerable | Reports other issues only | TN |

The last row follows Lenient Mode: `CORRECT` on a patched sample means that the report is accepted under this evaluation rule. It does not establish that the other reported issues are real vulnerabilities.

## Judge prompts and labels

For a **vulnerable function**, the judge returns:

- `MATCH`: the analysis includes the reference vulnerability's cause or identifies its key elements.
- `MISMATCH`: the analysis does not include the reference vulnerability and identifies unrelated issues only.

For a **patched function**, the judge returns:

- `FALSE_ALARM`: the analysis flags the already-fixed vulnerability. The patched-code prompt also explicitly includes the case where the rationale identifies a newly added patch line (a `+` line in the diff) as problematic.
- `CORRECT`: the rationale does not include the original vulnerability or refers to different issues, subject to the patched-code condition above.

The exact prompts are implemented in [`judge.py`](../src/vulinstruct/judge.py). Before/after labels are validated separately: an `after` response containing `MATCH` is not accepted as a substitute for `FALSE_ALARM`. An explicit conclusion may appear before or after its explanation, as a standalone label, a `Final judgment`/`Verdict` line, or a `match_result` tag. Conflicting conclusions and labels merely mentioned within prose are rejected. Lenient Mode does not perform the iterative detector feedback used by Strict Mode.

## Preparing the detector rationale

The detector is asked to place its review under `Analysis Process` and its assessment under `Final Conclusion`. Stage 2 prepares the input using the detector response parser's structure:

- Extract and HTML-unescape `<suspected_root_cause>` from `<vulnerability_assessment>`.
- Add the text from `Analysis Process` up to `Final Conclusion`, when both headings are present.
- Use the complete response when the assessment wrapper is absent, provided the detection fields still pass validation.

No explanation is fabricated from the predicted label. The prepared text is saved as `judge_input`, and the exact request prompt is saved as `judge_prompt`. The judge's returned explanation is `judge_rationale`; its parsed label is `judge`.

## Metrics and result validation

`metrics.json` contains two distinct metric groups:

- `binary`: ordinary classification using the detector's yes/no prediction.
- `correct_lenient`: the TP, FP, TN and FN assignments in the decision table. Use this group for CORRECT evaluation.

| Metric | Formula |
|---|---|
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 | 2TP / (2TP + FP + FN) |
| Accuracy | (TP + TN) / sample count |

Zero-denominator precision, recall and F1 are defined as zero. `binary_pairs` and `correct_pairs` report function-pair categories; see [Protocols](PROTOCOLS.md#metrics).

The evaluator requires complete benchmark coverage and complete before/after pairs. Request failures, missing judgments, invalid labels and labels for the wrong sample side prevent aggregate evaluation. They are not converted to TN or omitted. Each pipeline result records the judge protocol, configured judge model and implementation identity. A changed judge implementation invalidates saved sample-cache identities; results from different protocols must be evaluated separately.

## Evaluate a completed run

```sh
python -m vulinstruct evaluate --results runs/primevul-flash/results.json --benchmark data/benchmarks/primevul.jsonl.gz --output runs/primevul-flash/verified-metrics.json
```

This command checks recorded answers, judge inputs and benchmark coverage without new model calls. It does not rejudge previous answers or convert judgments from another protocol. The judge model is configured independently through `models.judge`; the example configuration uses `deepseek-flash`.

For a detection-only run created with `run --no-judge`, pass `--binary-only` to `evaluate`. That mode returns binary metrics only.
