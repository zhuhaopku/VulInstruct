"""Function-level identities and explicit benchmark/knowledge preparation."""
import difflib
import re
from collections import Counter

from .io import digest, rows, read_json, write_json, write_rows
from .nvd import timestamp


def code_key(code):
    # Whitespace-insensitive matching is used only for provenance joins, never to change code.
    return digest("".join(code.split()))


def pair_identity(repository, commit, filename, before, after):
    return digest([repository, commit, filename, code_key(before), code_key(after)])[:24]


def convert_primevul(source, output, contexts=None):
    """Convert the supplied official paired JSONL, validating every adjacent pair.

    The source pairs are stored as adjacent vulnerable/patched rows. We verify
    project and labels. Source CVE/commit conflicts are retained and flagged;
    those pairs require review before fresh ground-truth judging. Sorting or
    grouping by CVE is forbidden.
    """
    original = list(rows(source))
    if len(original) % 2:
        raise ValueError("PrimeVul paired source has an odd row count")
    context_map = {}
    if contexts:
        for c in read_json(contexts):
            for method in c.get("vulnerableMethods_before", []):
                for fixed in c.get("vulnerableMethods_after", []):
                    key = (c["cve_id"], c["commit_hash"], code_key(method["raw_code"]), code_key(fixed["raw_code"]))
                    context_map[key] = c.get("code_context", "")
    converted, seen = [], set()
    for offset in range(0, len(original), 2):
        before, after = original[offset:offset + 2]
        if (before["target"], after["target"]) != (1, 0):
            raise ValueError("Expected adjacent vulnerable/patched source rows at " + str(offset))
        if before["project"] != after["project"]:
            raise ValueError("Source pair has conflicting projects")
        conflicts = {k: [before[k], after[k]] for k in ("cve", "commit_id") if before[k] != after[k]}
        before_file = before["file_name"] if before["file_name"] not in (None, "None", "") else after["file_name"]
        after_file = after["file_name"] if after["file_name"] not in (None, "None", "") else before_file
        pid = pair_identity(before["project"], before["commit_id"], [before_file, after_file], before["func"], after["func"])
        if pid in seen:
            raise ValueError("Duplicate source function pair")
        seen.add(pid)
        key = (before["cve"], before["commit_id"], code_key(before["func"]), code_key(after["func"]))
        context = context_map.get(key, "")
        patch = "\n".join(difflib.unified_diff(before["func"].splitlines(), after["func"].splitlines(),
                                               fromfile="a/" + str(before_file), tofile="b/" + str(after_file), lineterm=""))
        gt = {"cve_description": before["cve_desc"], "commit_message": before["commit_message"],
              "commit_hash": before["commit_id"], "filename": before_file, "code_diff": patch}
        for side, record in (("before", before), ("after", after)):
            converted.append({"sample_id": "primevul-" + str(record["idx"]) + "-" + pid + "-" + side, "pair_id": pid,
                              "source_idx": record["idx"], "cve_id": before["cve"], "code_type": side,
                              "true_label": record["target"], "repository": record["project"],
                              "commit_hash": before["commit_id"], "filename": before_file if side == "before" else after_file,
                              "source_metadata": {k: record[k] for k in ("cve", "commit_id", "file_name")},
                              "source_metadata_conflicts": conflicts,
                              "code": record["func"], "context": context,
                              "context_status": "archived" if context else "unavailable",
                              "ground_truth_status": "requires_review" if conflicts else "source_pair",
                              "ground_truth": gt})
    write_rows(output, converted)
    manifest = {"samples": len(converted), "pairs": len(seen),
                "unique_cves": len({r["cve_id"] for r in converted}),
                "context_status": dict(Counter(r["context_status"] for r in converted)),
                "identity": "sample=source idx+pair hash+side; pair=hash(project,commit,files,before,after)",
                "duplicate_source_indices": {str(k): v for k, v in Counter(r['idx'] for r in original).items() if v > 1},
                "source_cve_grouping_used": False,
                "source_metadata_conflict_pairs": len({s["pair_id"] for s in converted if s["source_metadata_conflicts"]})}
    write_json(str(output) + ".manifest.json", manifest)
    return converted, manifest


def normalize_corpus(source):
    data = read_json(source)
    if isinstance(data, dict):
        data = data.get("cases", data.get("entries", []))
        if isinstance(data, dict):
            data = list(data.values())
    if not isinstance(data, list) or not data:
        raise ValueError('Expected a non-empty knowledge corpus')
    result = []
    for r in data:
        item = {"case_id": r["case_id"], "cve_id": r["cve_id"], "repository": r.get("repository", ""),
                "commit_hash": r.get("commit_hash", ""), "understand": r.get("understand", ""),
                "specifications": r.get("specifications", []), "threat_model": r.get("threat_model", ""),
                "vulnerability_analysis": r.get("vulnerability_analysis", ""),
                "solution_analysis": r.get("solution_analysis", ""),
                "code": r.get("code", ""), "split": r.get("split", "train")}
        if not isinstance(item['understand'], str) or not item['understand'].strip() or not isinstance(item['specifications'], list) or not item['specifications'] or any(not isinstance(s, str) or not s.strip() for s in item['specifications']):
            raise ValueError("Incomplete knowledge case: " + item["case_id"])
        result.append(item)
    if len({r["case_id"] for r in result}) != len(result):
        raise ValueError("Duplicate knowledge case identity")
    return result


def convert_sven(source, output):
    original = list(rows(source))
    if len(original) % 2:
        raise ValueError("Odd SVEN row count")
    converted, excluded = [], []
    extensions = ('.c', '.cpp', '.cc', '.h', '.hpp', '.cxx', '.hxx')
    for offset in range(0, len(original), 2):
        a, b = original[offset:offset + 2]
        if (a['target'], b['target']) != (1, 0) or a['func_name'] != b['func_name']:
            raise ValueError("Conflicting SVEN function pair at source line " + str(offset + 1))
        if not a['file_name'].endswith(extensions):
            excluded.append(offset + 1)
            continue
        link = a.get('commit_link', '')
        match = re.search(r'github\.com/([^/]+/[^/]+)/commit/([a-fA-F0-9]+)', link)
        repository, commit = match.groups() if match else ('', '')
        pid = pair_identity(repository, commit or link, [a['file_name'], b['file_name']], a['func'], b['func'])
        patch = '\n'.join(difflib.unified_diff(a['func'].splitlines(), b['func'].splitlines(),
                            fromfile='a/' + a['file_name'], tofile='b/' + b['file_name'], lineterm=''))
        for side, record in (('before', a), ('after', b)):
            converted.append({'sample_id': f'sven-{offset + 1}-{pid}-{side}', 'pair_id': pid,
                'legacy_case_id': f'sven_{offset + 1}_{a["func_name"]}_{side}',
                'source_line': offset + 1 if side == 'before' else offset + 2,
                'cve_id': None, 'code_type': side, 'true_label': record['target'],
                'repository': repository, 'commit_hash': commit, 'filename': record['file_name'],
                'code': record['func'], 'context': '', 'context_status': 'unavailable',
                'ground_truth_status': 'patch_only', 'commit_link': link,
                'ground_truth': {'cve_description': 'CVE description unavailable. Source CWE label: ' + a['vul_type'],
                    'commit_message': 'Commit message unavailable; consult commit_link.',
                    'commit_link': link, 'code_diff': patch}})
    if len({s['sample_id'] for s in converted}) != len(converted):
        raise ValueError("Duplicate SVEN sample identities")
    write_rows(output, converted)
    manifest = {'samples': len(converted), 'pairs': len(converted) // 2,
        'source_rows': len(original), 'excluded_non_cpp_pair_start_lines': excluded,
        'ground_truth': 'patch and source CWE only; no CVE or fabricated commit message',
        'temporal': 'No publication dates in source. Fresh runs require an explicitly declared as-of date.'}
    write_json(str(output) + '.manifest.json', manifest)
    return converted, manifest


def filter_corpus(source, output, nvd_index, benchmark, before=None):
    cases = normalize_corpus(source)
    samples = list(rows(benchmark))
    excluded = {s["cve_id"] for s in samples if s.get('cve_id')}
    excluded_commits = {s['commit_hash'] for s in samples if s.get('commit_hash')}
    # Without a global cutoff, the detector applies the target's publication
    # cutoff to every general candidate before ranking. Do not invent a split date.
    cutoff = timestamp(before) if before else None
    retained, decisions = [], []
    for r in cases:
        metadata = nvd_index.get(r["cve_id"])
        reason = None
        if r["split"] != "train":
            reason = "non_training_split"
        elif r["cve_id"] in excluded:
            reason = "benchmark_cve_overlap"
        elif r.get('commit_hash') in excluded_commits:
            reason = "benchmark_commit_overlap"
        elif metadata is None:
            reason = "missing_publication_date"
        elif metadata.get('status') == 'Rejected':
            reason = "rejected_cve"
        elif cutoff and timestamp(metadata["published"]) >= cutoff:
            reason = "not_before_cutoff"
        if reason:
            decisions.append({"case_id": r["case_id"], "reason": reason})
        else:
            r["published"] = metadata["published"]
            retained.append(r)
    if not retained:
        raise ValueError("No knowledge cases satisfy the declared protocol")
    write_json(output, retained)
    manifest = {"input_count": len(cases), "retained": len(retained), "cutoff": cutoff,
                "temporal_policy": "global-and-per-query" if cutoff else "per-query",
                "excluded_benchmark_cves": sorted(excluded), "decisions": decisions,
                "reason_counts": dict(Counter(x["reason"] for x in decisions))}
    write_json(str(output) + ".manifest.json", manifest)
    return manifest
