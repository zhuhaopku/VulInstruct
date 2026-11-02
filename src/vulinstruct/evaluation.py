"""CORRECT-style metrics, binary metrics and strict function-pair validation."""
import re
from collections import Counter, defaultdict
from .judge import JUDGE_PROTOCOL

JUDGE_LABELS = {"before": {"MATCH", "MISMATCH"}, "after": {"FALSE_ALARM", "CORRECT"}}


class EvaluationError(ValueError):
    pass


def parse_detection(text):
    matches = re.findall(r"<has_vulnerability>(.*?)</has_vulnerability>", text, re.I | re.S)
    if len(matches) != 1 or matches[0].strip().lower() not in ("yes", "no"):
        raise EvaluationError("Detection must contain exactly one yes/no assessment")
    causes = re.findall(r"<suspected_root_cause>(.*?)</suspected_root_cause>", text, re.S)
    if len(causes) != 1 or not causes[0].strip():
        raise EvaluationError("Detection is missing its root-cause rationale")
    return {"prediction": int(matches[0].strip().lower() == "yes"), "rationale": causes[0].strip(),
            "raw_response": text}


def parse_judge(text, code_type=None):
    """Require an unambiguous explicit conclusion, before or after explanation."""
    tags = re.findall(r"<match_result>(.*?)</match_result>", text, re.I | re.S)
    labels = JUDGE_LABELS["before"] | JUDGE_LABELS["after"]
    conclusions = []
    if tags:
        if len(tags) != 1 or tags[0].strip().upper() not in labels:
            raise EvaluationError("Invalid or multiple judge conclusions")
        conclusions.append(tags[0].strip().upper())
    for line in text.splitlines():
        line = re.sub(r"[*`]", "", line).strip().strip(" .\"'")
        match = re.fullmatch(r"(?:(?:Final (?:judgment|judgement|answer|verdict)|Conclusion|Result|Judgment|Judgement|Verdict)\s*:\s*)?[\"']?(MATCH|MISMATCH|FALSE_ALARM|CORRECT)[\"']?", line, re.I)
        if match:
            conclusions.append(match.group(1).upper())
    if not conclusions:
        raise EvaluationError("Missing explicit judge conclusion; mark judge failure, not TN")
    if len(set(conclusions)) != 1:
        raise EvaluationError("Conflicting explicit judge conclusions")
    verdict = conclusions[0]
    if code_type is not None:
        if code_type not in JUDGE_LABELS or verdict not in JUDGE_LABELS[code_type]:
            raise EvaluationError("Judge label conflicts with code_type: " + str(code_type))
    return verdict


def confusion(labels):
    counts = Counter({"tp": 0, "fp": 0, "tn": 0, "fn": 0})
    for truth, pred in labels:
        if type(truth) not in (int, bool) or truth not in (0, 1) or type(pred) not in (int, bool) or pred not in (0, 1):
            raise EvaluationError("Labels must be binary integers")
        counts[{(1, 1): "tp", (0, 1): "fp", (0, 0): "tn", (1, 0): "fn"}[(truth, pred)]] += 1
    tp, fp, tn, fn = (counts[k] for k in ("tp", "fp", "tn", "fn"))
    n = tp + fp + tn + fn
    return {"confusion_matrix": dict(counts), "n": n,
            "accuracy": (tp + tn) / n if n else None,
            "precision": tp / (tp + fp) if tp + fp else 0.0,
            "recall": tp / (tp + fn) if tp + fn else 0.0,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0}


def effective_prediction(row):
    pred = row.get("prediction")
    if type(pred) not in (int, bool) or pred not in (0, 1):
        raise EvaluationError("Missing or invalid prediction for " + str(row.get("sample_id")))
    if pred == 0:
        return 0
    verdict = row.get("judge", row.get("stage2_match_result"))
    side = row.get("code_type")
    if side == "before" and verdict in JUDGE_LABELS["before"]:
        return int(verdict == "MATCH")
    if side == "after" and verdict in JUDGE_LABELS["after"]:
        return int(verdict == "FALSE_ALARM")
    raise EvaluationError("Positive prediction has no valid judge result: " + str(row.get("sample_id")))


def pair_metrics(pairs):
    counts = Counter({"P-C": 0, "P-V": 0, "P-B": 0, "P-R": 0})
    for before, after in pairs:
        counts[{(1, 0): "P-C", (1, 1): "P-V", (0, 0): "P-B", (0, 1): "P-R"}[(before, after)]] += 1
    n = sum(counts.values())
    return {"n_pairs": n, "counts": dict(counts),
            "rates": {k: v / n if n else None for k, v in counts.items()},
            "VP-S": (counts["P-C"] - counts["P-R"]) / n if n else None}


def evaluate(records, expected_ids=None, require_judge=True):
    """Validate every sample and require exactly one before/after per pair."""
    if not records:
        raise EvaluationError("No evaluation records")
    judge_protocols = {row.get("judge_protocol") for row in records}
    if require_judge and (len(judge_protocols) != 1 or not judge_protocols <= {None, JUDGE_PROTOCOL}):
        raise EvaluationError("Mixed or unsupported judge protocols; evaluate each run separately")
    seen = set()
    groups = defaultdict(dict)
    basic, correct = [], []
    for row in records:
        sid, pid, side = row.get("sample_id"), row.get("pair_id"), row.get("code_type")
        if not sid or sid in seen:
            raise EvaluationError("Missing or duplicate sample_id: " + str(sid))
        seen.add(sid)
        if not pid or side not in ("before", "after") or side in groups[pid]:
            raise EvaluationError("Missing/duplicate function-pair identity: " + str(pid))
        if row.get("status", "ok") != "ok":
            raise EvaluationError("Failed sample cannot be scored: " + str(sid))
        truth = int(side == "before")
        if row.get("true_label", truth) != truth:
            raise EvaluationError("Ground-truth label conflicts with code_type")
        if type(row.get('prediction')) not in (int, bool) or row['prediction'] not in (0, 1):
            raise EvaluationError('Invalid binary prediction')
        effective = effective_prediction(row) if require_judge else row['prediction']
        basic.append((truth, row["prediction"]))
        correct.append((truth, effective))
        groups[pid][side] = (row["prediction"], effective)
    if expected_ids is not None and seen != set(expected_ids):
        raise EvaluationError("Result coverage differs from benchmark manifest")
    incomplete = [k for k, v in groups.items() if set(v) != {"before", "after"}]
    if incomplete:
        raise EvaluationError("Incomplete function pairs: " + ", ".join(incomplete[:5]))
    result = {"protocol": "correct-lenient/function-pairs-v1", "n_samples": len(records),
            "judge_protocol": next(iter(judge_protocols)),
            "binary": confusion(basic), "correct_lenient": confusion(correct),
            "binary_pairs": pair_metrics((v["before"][0], v["after"][0]) for v in groups.values()),
            "correct_pairs": pair_metrics((v["before"][1], v["after"][1]) for v in groups.values())}
    if not require_judge:
        result['protocol'] = 'binary-only/function-pairs-v1'
        del result['correct_lenient'], result['correct_pairs']
        del result['judge_protocol']
    return result

