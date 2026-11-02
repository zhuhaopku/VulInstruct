"""Specification-guided detection with audited retrieval and judge isolation."""
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import prompts, prompts_v1, prompts_v2, prompts_v3
from .evaluation import parse_detection, parse_judge
from .judge import JUDGE_PROTOCOL, build_judge_prompt, prepare_rationale
from .io import digest, file_digest, read_json, write_json
from .nvd import timestamp


def json_response(text):
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def _one_edit(left,right):
    if len(left)==len(right):return sum(a!=b for a,b in zip(left,right))==1
    if abs(len(left)-len(right))!=1:return False
    short,long=(left,right) if len(left)<len(right) else (right,left)
    offset=next((i for i,(a,b) in enumerate(zip(short,long)) if a!=b),len(short))
    return short[offset:]==long[offset+1:]


def validate_scores(response, candidates):
    scores = json_response(response).get("scores")
    if not isinstance(scores, list):
        raise ValueError("Missing knowledge scores")
    expected = {r["id"] for r in candidates}
    actual = [r.get("id") for r in scores]
    # Foreign-key transcription repair only: a unique one-character typo in an
    # opaque hash suffix. Never change CVE identity, score, reason, or list length.
    if len(actual)==len(expected) and len(set(actual))==len(actual):
        missing=expected-set(actual)
        repairs={}
        for supplied in set(actual)-expected:
            if not isinstance(supplied,str):continue
            match=re.fullmatch(r'(CVE-\d{4}-\d+_)([a-f0-9]{7,9})|(spec-)([a-f0-9]{19,21})',supplied)
            if not match:continue
            prefix=match.group(1) or match.group(3)
            choices=[target for target in missing if target.startswith(prefix) and _one_edit(target,supplied)]
            if len(choices)==1:repairs[supplied]=choices[0]
        if len(repairs)==len(set(actual)-expected) and len(set(repairs.values()))==len(repairs):
            for score in scores:
                if score.get('id') in repairs:
                    score['reported_id']=score['id'];score['id']=repairs[score['id']]
            actual=[r.get('id') for r in scores]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise ValueError("Knowledge scores omitted/duplicated/invented candidate IDs")
    for s in scores:
        if type(s.get("score")) is not int or not 1 <= s["score"] <= 10:
            raise ValueError("Knowledge score must be an integer 1-10")
    return scores


def selected_items(client, model, sample, candidates, kind, threshold, prompt_module=prompts, repairs=None):
    if not candidates or threshold > 10:
        return [], []
    prompt = prompt_module.score(sample, candidates, kind)
    response = client.ask(prompt, model, "score-" + kind)
    for attempt in range(3):
        try:
            scores = validate_scores(response, candidates)
            break
        except (ValueError, TypeError, AttributeError) as exc:
            if attempt == 2:
                raise ValueError("Invalid knowledge scores after bounded format repair: " + str(exc)) from exc
            if repairs is not None:
                repairs.append({"error": str(exc), "response": response})
            correction = (prompt + "\nPREVIOUS INVALID RESPONSE:\n" + response
                + "\nVALIDATION ERROR: " + str(exc)
                + "\nReturn valid JSON with each exact supplied ID once and integer scores in [1,10]. "
                  "Preserve valid relevance judgments. Correct only schema, transcription and missing entries; "
                  "do not change judgments to retain more or fewer candidates.")
            response = client.ask(correction, model, "score-" + kind + "-format-repair")
    keep = {s["id"] for s in scores if s["score"] >= threshold}
    return [r for r in candidates if r["id"] in keep], scores


def validate_domain_specs(value, candidates):
    specs = value.get("specifications")
    if not isinstance(specs, list):
        raise ValueError("Missing domain specifications")
    allowed = {r["cve_id"] for r in candidates}
    seen = set()
    for spec in specs:
        sid = spec.get("id", "")
        refs = spec.get("supporting_cves", [])
        if not re.fullmatch(r"AS-[A-Z0-9_-]+-\d+", sid) or sid in seen:
            raise ValueError("Invalid/duplicate AS specification ID")
        seen.add(sid)
        if not isinstance(refs, list) or len(set(refs)) < 2 or not set(refs) <= allowed:
            raise ValueError("Recurring domain specification must cite at least two retrieved CVEs")
        if not all(isinstance(spec.get(k), str) and spec[k].strip() for k in ("statement", "attack_pattern")):
            raise ValueError("Domain specification lacks mechanism or safe behavior")
    return specs


class Pipeline:
    def __init__(self, client, dense, nvd, config):
        self.client, self.dense, self.nvd, self.config = client, dense, nvd, config
        self.embedding_lock = threading.Lock()
        self.models = config["models"]
        protocol = config.get('prompt_protocol', prompts.PROMPT_VERSION)
        versions = {m.PROMPT_VERSION: m for m in (prompts, prompts_v1, prompts_v2, prompts_v3)}
        if protocol not in versions:
            raise ValueError('Unknown prompt_protocol: ' + str(protocol))
        self.prompts = versions[protocol]
        self.thresholds = config.get("thresholds", {"cases": 6, "specifications": 6, "nvd": 6})
        if set(self.thresholds) != {"cases", "specifications", "nvd"} or any(type(x) not in (int, float) or not 1 <= x <= 11 for x in self.thresholds.values()):
            raise ValueError("Declare all three thresholds in [1,11]; 11 disables a knowledge channel")
        source_root = Path(__file__).resolve().parent
        source_files = [source_root / name for name in ('pipeline.py', 'nvd.py', 'retrieval.py',
                       'evaluation.py', 'judge.py', 'llm.py', 'io.py')]
        source_files.append(Path(self.prompts.__file__).resolve())
        self.implementation = {p.name: file_digest(p) for p in source_files}
        self.fingerprint = digest({"config": config, "prompt_version": self.prompts.PROMPT_VERSION,
                                   "pipeline_version": "0.5.7", "judge_protocol": JUDGE_PROTOCOL,
                                   "implementation": self.implementation,
                                   "general_index": dense.manifest, "nvd_index": nvd.manifest})

    def ask_final(self, prompt, role, stage):
        """Declared, bounded recovery only for incomplete textual output.

        Never retry a completed assessment because of its prediction or score.
        Invalid transport responses are cached separately from successful text.
        """
        try:
            return self.client.ask(prompt, self.models[role], stage), None
        except ValueError as exc:
            retry_stage = stage + '-output-retry'
            retry_budget = self.config.get('stage_max_output_tokens', {}).get(retry_stage, 0)
            original_budget = self.config.get('stage_max_output_tokens', {}).get(stage,
                self.config.get('max_output_tokens', 4096))
            if str(exc) not in ('Model output truncated; increase max_output_tokens',
                                'Model returned no textual response') or retry_budget <= original_budget:
                raise
            meta = {'stage': stage, 'error': str(exc), 'retry_stage': retry_stage,
                    'original_max_output_tokens': original_budget,
                    'retry_max_output_tokens': retry_budget}
            try:
                text = self.client.ask(prompt, self.models[role], retry_stage)
            except ValueError as retry_error:
                fallback_stage = stage + '-output-fallback'
                options = self.config.get('stage_request_options', {}).get(fallback_stage, {})
                if str(retry_error) not in ('Model output truncated; increase max_output_tokens',
                                            'Model returned no textual response') or options.get('reasoning_effort') != 'low':
                    raise
                # Same prompt/model and evidence, lower reasoning effort only after
                # both output budgets fail. Completed judgments never enter here.
                meta.update(fallback_stage=fallback_stage, fallback_error=str(retry_error),
                    fallback_reasoning_effort='low',
                    fallback_max_output_tokens=self.config.get('stage_max_output_tokens', {}).get(
                        fallback_stage, self.config.get('max_output_tokens', 4096)))
                try:
                    text = self.client.ask(prompt, self.models[role], fallback_stage)
                except ValueError as fallback_error:
                    direct_stage = stage + '-output-direct'
                    direct_options = self.config.get('stage_request_options', {}).get(direct_stage, {})
                    if str(fallback_error) not in ('Model output truncated; increase max_output_tokens',
                                                  'Model returned no textual response') or direct_options.get('thinking', {}).get('type') != 'disabled':
                        raise
                    meta.update(direct_stage=direct_stage, direct_error=str(fallback_error),
                        direct_thinking='disabled', direct_max_output_tokens=self.config.get(
                            'stage_max_output_tokens', {}).get(direct_stage,
                            self.config.get('max_output_tokens', 4096)))
                    try:
                        text = self.client.ask(prompt, self.models[role], direct_stage)
                    except ValueError as direct_error:
                        last_stage = direct_stage + '-retry'
                        last_options = self.config.get('stage_request_options', {}).get(last_stage, {})
                        last_budget = self.config.get('stage_max_output_tokens', {}).get(last_stage, 0)
                        if str(direct_error) not in ('Model output truncated; increase max_output_tokens',
                                                    'Model returned no textual response') or last_options.get('thinking', {}).get('type') != 'disabled' or last_budget <= meta['direct_max_output_tokens']:
                            raise
                        # A large function can need a longer final review even with
                        # thinking disabled. This is the final declared attempt.
                        text = self.client.ask(prompt, self.models[role], last_stage)
                        meta.update(direct_retry_stage=last_stage,
                            direct_retry_error=str(direct_error),
                            direct_retry_max_output_tokens=last_budget)
            return text, meta

    def run_sample(self, sample, include_judge=True):
        prompts = self.prompts
        if sample.get('code_type') not in ('before', 'after'):
            raise ValueError("Sample requires a before/after code type")
        if include_judge and sample.get("ground_truth_status") == "requires_review":
            raise ValueError("Source pair has conflicting metadata; review ground truth before fresh judging")
        if include_judge and sample.get('ground_truth_status') == 'patch_only' and not self.config.get('allow_patch_only_judge', False):
            raise ValueError("Patch-only SVEN judging requires explicit allow_patch_only_judge=true; it is a distinct protocol")
        cid = sample.get("cve_id")
        cutoff = sample.get("published") or self.config.get("before")
        if not cutoff and cid:
            metadata = self.nvd.get(cid)
            cutoff = metadata["published"] if metadata else None
        if not cutoff:
            raise ValueError("An explicit as-of date or known target CVE is required")
        cutoff = timestamp(cutoff)
        if include_judge:
            gt = sample.get("ground_truth", {})
            if not all(gt.get(k) for k in ("cve_description", "commit_message", "code_diff")):
                raise ValueError("Missing ground-truth evidence for CORRECT judge")
        response = self.client.ask(prompts.understanding(sample), self.models["knowledge"], "understand")
        matches = re.findall(r"<understand>(.*?)</understand>", response, re.S)
        if len(matches) != 1 or not matches[0].strip():
            raise ValueError("Missing structured system understanding")
        understand = matches[0].strip()
        top_k = self.config.get("top_k", 10)
        with self.embedding_lock:
            general = self.dense.search(understand, sample["code"], top_k, target_cve=cid, before=cutoff,
                                        exclude_commit=sample.get('commit_hash'))
        query = json_response(self.client.ask(prompts.keywords(sample, understand), self.models["knowledge"], "keywords"))
        if any(not isinstance(query.get(k), list) or any(not isinstance(x, str) for x in query[k]) for k in ("identifiers", "domain_terms")):
            raise ValueError("Invalid identifier/domain keyword response")
        keywords = query["identifiers"] + query["domain_terms"]
        if not keywords:
            raise ValueError("Empty keyword extraction")
        if prompts.PROMPT_VERSION == 'corrected-v1':
            domain = self.nvd.search(keywords, target_cve=cid, before=cutoff, top_k=top_k,
                                     max_frequency=self.config.get("max_keyword_frequency", 500))
        else:
            if not isinstance(query.get('products', []), list) or any(not isinstance(x, str) for x in query.get('products', [])):
                raise ValueError('Invalid product keyword response')
            domain = self.nvd.search_domain(query, repository=sample.get('repository', ''),
                target_cve=cid, before=cutoff, top_k=top_k,
                max_frequency=self.config.get('max_keyword_frequency', 500))
        cases = [{"id": r["case_id"], **r} for r in general]
        specs, seen = [], set()
        for case in general:
            for text in case["specifications"]:
                identity = digest(text)
                if identity not in seen:
                    seen.add(identity)
                    specs.append({"id": "spec-" + identity[:20], "statement": text, "source_cve": case["cve_id"]})
        nvd_cases = [{"id": r["cve_id"], **r} for r in domain["results"]]
        groups = {"cases": cases, "specifications": specs, "nvd": nvd_cases}
        score_repairs = {kind: [] for kind in groups}
        def score_group(kind):
            return kind, selected_items(self.client, self.models["knowledge"], sample,
                                       groups[kind], kind, self.thresholds[kind], prompts, score_repairs[kind])
        workers = max(1, min(int(self.config.get("score_workers", 3)), 3))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            scored = dict(pool.map(score_group, groups))
        selected = {k: pair[0] for k, pair in scored.items()}
        # Keep applicable general specs even if every detailed case scored below threshold.
        attack_specs = []
        if len(selected["nvd"]) >= 2:
            domain_prompt=prompts.domain_specifications(selected["nvd"])
            response = self.client.ask(domain_prompt, self.models["knowledge"], "domain-specifications")
            repairs=[]
            for attempt in range(3):
                try:
                    attack_specs = validate_domain_specs(json_response(response), selected["nvd"])
                    break
                except ValueError as exc:
                    if attempt==2:raise
                    repairs.append({'error':str(exc),'response':response})
                    repair_prompt=domain_prompt+'\nPREVIOUS INVALID RESPONSE:\n'+response+'\nVALIDATION ERROR: '+str(exc)+'\nReturn corrected JSON. Do not invent supporting evidence. Omit unsupported specifications; an empty specifications array is valid when no recurring mechanism has two supporting retrieved CVEs.'
                    response=self.client.ask(repair_prompt,self.models['knowledge'],'domain-specifications-format-repair')
        knowledge = {**selected, "domain_specifications": attack_specs}
        response, detection_retry = self.ask_final(prompts.detection(sample, knowledge), 'detector', 'detect')
        draft = None
        if prompts.PROMPT_VERSION == 'domain-cascade-v3':
            # Every sample gets the same review stage, irrespective of draft label or truth.
            parse_detection(response)
            draft = response
            response = self.client.ask(prompts.review_detection(sample, knowledge, draft),
                                       self.models['detector'], 'detect-review')
        result = parse_detection(response)
        if detection_retry:
            result['detection_output_retry'] = detection_retry
        if draft is not None:
            result['detection_draft'] = draft
        result.update({k: sample.get(k) for k in ("sample_id", "pair_id", "cve_id", "code_type", "true_label")})
        result.update({"status": "ok", "protocol": prompts.PROMPT_VERSION, "understand": understand,
                       "ground_truth_status": sample.get('ground_truth_status'),
                       "retrieval": {"keywords": query, "general": general, "nvd": domain},
                       "scoring": {k: p[1] for k, p in scored.items()}, "knowledge": knowledge,
                       "pipeline_hash": self.fingerprint, "sample_hash": digest(sample)})
        result['implementation_hash'] = digest(self.implementation)
        result['judge_protocol'] = JUDGE_PROTOCOL if include_judge else None
        result['judge_model'] = self.models['judge'] if include_judge else None
        if any(score_repairs.values()):result['score_format_repairs']=score_repairs
        if len(selected['nvd'])>=2 and repairs:result['domain_format_repairs']=repairs
        if include_judge and result["prediction"]:
            judge_input = prepare_rationale(result['raw_response'])
            judge_prompt = build_judge_prompt(sample['ground_truth'], judge_input, sample['code_type'])
            judge_response, judge_retry = self.ask_final(judge_prompt, 'judge', 'judge')
            if judge_retry:
                result['judge_output_retry'] = judge_retry
            result.update(judge_input_scope='stage1_reasoning', judge_input=judge_input,
                          judge_prompt=judge_prompt, judge_rationale=judge_response,
                          judge=parse_judge(judge_response, sample['code_type']))
        else:
            result["judge"] = "NOT_NEEDED" if include_judge else "NOT_RUN"
        return result

    def run(self, samples, output, include_judge=True, retry_errors=False):
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        # An interrupted or failed rerun must not leave an older successful score.
        (output / 'metrics.json').unlink(missing_ok=True)
        (output / 'results.json').unlink(missing_ok=True)
        started = time.monotonic()
        progress, lock = {'total': len(samples), 'completed': 0, 'errors': 0, 'reused': 0}, threading.Lock()
        write_json(output / 'progress.json', progress)
        def run_one(sample):
            run_hash = digest({"sample": sample, "pipeline": self.fingerprint, "judge": include_judge})
            path = output / (run_hash + ".json")
            if path.exists():
                old = read_json(path)
                if old.get('pipeline_hash') != self.fingerprint or old.get('sample_id') != sample['sample_id']:
                    raise ValueError('Sample cache identity mismatch')
                if old.get('status') == 'ok' and old.get('sample_hash') != digest(sample):
                    raise ValueError('Sample cache content mismatch')
                if old.get("status") == "ok" or not retry_errors:
                    with lock:
                        progress['reused'] += 1
                        progress['completed'] += 1
                        progress['errors'] += int(old.get('status') != 'ok')
                    return old
            try:
                result = self.run_sample(sample, include_judge)
            except Exception as exc:
                result = {k: sample.get(k) for k in ("sample_id", "pair_id", "cve_id", "code_type", "true_label")}
                result.update(status="error", error=str(exc), pipeline_hash=self.fingerprint)
            write_json(path, result)
            with lock:
                progress['completed'] += 1
                progress['errors'] += int(result['status'] != 'ok')
                progress['elapsed_seconds'] = time.monotonic() - started
                if hasattr(self.client, 'stats'):
                    progress['transport'] = self.client.stats()
                write_json(output / 'progress.json', progress)
            print(sample["sample_id"] + ": " + result["status"], flush=True)
            return result
        workers = self.config.get('sample_workers', 1)
        if type(workers) is not int or workers < 1 or workers > 32:
            raise ValueError('sample_workers must be an integer in [1,32]')
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(run_one, samples))
        write_json(output / "results.json", results)
        progress['elapsed_seconds'] = time.monotonic() - started
        if hasattr(self.client, 'stats'):
            progress['transport'] = self.client.stats()
        write_json(output / 'progress.json', progress)
        return results
