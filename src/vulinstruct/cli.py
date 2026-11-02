import argparse
import importlib.util
import json
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

from .datasets import convert_primevul, convert_sven, filter_corpus
from .evaluation import evaluate, parse_detection, parse_judge
from .judge import JUDGE_PROTOCOL, build_judge_prompt, prepare_rationale
from .io import digest, file_digest, read_json, rows, write_json
from .nvd import NVDIndex, build_index, normalize_feeds
from .preflight import check_samples, load_config, preflight, select_samples


def emit(value, output=None):
    if output:
        write_json(output, value)
    print(json.dumps(value, ensure_ascii=False, indent=2))


def model_args(parser):
    parser.add_argument("--model", default="Qwen/Qwen3-Embedding-0.6B")
    parser.add_argument("--revision", default="c54f2e6e80b2d7b7de06f51cec4959f6b3e03418")
    parser.add_argument("--device")


def nvd_args(parser):
    parser.add_argument("--index", required=True)
    parser.add_argument("--publication-metadata")


def make_client(config, max_calls, refresh_cache=False):
    from .llm import LLMClient
    return LLMClient(config["base_url"], key_env=config.get("key_env", "VULINSTRUCT_API_KEY"),
                     cache_dir=config.get("cache_dir", "runs/api-cache"), max_calls=max_calls,
                     timeout=config.get("timeout", 180), retries=config.get("retries", 2),
                     max_output_tokens=config.get("max_output_tokens", 4096), refresh_cache=refresh_cache,
                     request_options=config.get('request_options'), allow_http=config.get('allow_http', False),
                     stage_request_options=config.get('stage_request_options'),
                     stage_max_output_tokens=config.get('stage_max_output_tokens'))


def main(argv=None):
    parser = argparse.ArgumentParser(description="VulInstruct vulnerability detection and evaluation")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("evaluate", help="Strictly validate and score canonical function pairs")
    p.add_argument("--results", required=True)
    p.add_argument("--benchmark", required=True)
    p.add_argument("--output")
    p.add_argument("--binary-only", action="store_true")
    p = sub.add_parser("normalize-nvd")
    p.add_argument("--feeds", required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("index-nvd")
    p.add_argument("--corpus", required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("query-nvd")
    nvd_args(p)
    p.add_argument("--keywords", nargs="+", required=True)
    p.add_argument("--target-cve")
    p.add_argument("--before")
    p.add_argument("--top-k", type=int, default=10)
    p.add_argument("--max-frequency", type=int, default=500)
    p.add_argument("--output")
    p = sub.add_parser("query-domain", help="Inspect product/component NVD retrieval")
    nvd_args(p)
    p.add_argument("--repository", default="")
    p.add_argument("--products", nargs="*", default=[])
    p.add_argument("--identifiers", nargs="*", default=[])
    p.add_argument("--domain-terms", nargs="*", default=[])
    p.add_argument("--target-cve")
    p.add_argument("--before")
    p.add_argument("--top-k", type=int, default=10)
    p.add_argument("--max-frequency", type=int, default=500)
    p.add_argument("--output")
    p = sub.add_parser("prepare-primevul")
    p.add_argument("--source", required=True)
    p.add_argument("--contexts")
    p.add_argument("--output", required=True)
    p = sub.add_parser("prepare-sven")
    p.add_argument("--source", required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("prepare-corpus")
    p.add_argument("--source", required=True)
    p.add_argument("--benchmark", required=True)
    p.add_argument("--before")
    nvd_args(p)
    p.add_argument("--output", required=True)
    p = sub.add_parser("fetch-hf")
    p.add_argument("--output", required=True)
    p.add_argument("--parquet", help="Import a local pinned Parquet instead of downloading")
    p = sub.add_parser("index-specs")
    p.add_argument("--corpus", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--include-code", action="store_true")
    model_args(p)
    p = sub.add_parser("extract-kb")
    p.add_argument("--source", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--limit", type=int)
    p.add_argument("--scope", choices=["all-methods", "legacy-first-method"], default="all-methods")
    p.add_argument("--max-calls", type=int, default=10)
    p.add_argument("--refresh-api-cache", action="store_true")
    p = sub.add_parser("run")
    p.add_argument("--benchmark", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--pairs", type=int, help="Run the first N complete pairs; omit for all")
    p.add_argument("--max-calls", type=int, default=100)
    p.add_argument("--no-judge", action="store_true")
    p.add_argument("--retry-errors", action="store_true")
    p.add_argument("--refresh-api-cache", action="store_true", help="Re-request cached responses for retried/missing samples")
    p = sub.add_parser("doctor")
    p.add_argument("--root", default=".")
    p = sub.add_parser('preflight', help='Check all benchmark and retrieval inputs without API calls or model weights')
    p.add_argument('--benchmark', required=True)
    p.add_argument('--config', required=True)
    p.add_argument('--output')
    p.add_argument('--pairs', type=int)
    p.add_argument('--no-judge', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == "evaluate":
            if args.output:
                if Path(args.output).resolve() in {Path(args.results).resolve(), Path(args.benchmark).resolve()}:
                    raise ValueError('Evaluation output must not overwrite either input')
                Path(args.output).unlink(missing_ok=True)
            result = list(rows(args.results))
            benchmark = list(rows(args.benchmark))
            evaluate([dict(s, prediction=0, status='ok') for s in benchmark], require_judge=False)
            by_id = {r["sample_id"]: r for r in benchmark}
            for r in result:
                truth = by_id.get(r.get("sample_id"))
                if truth is None or any(r.get(k) != truth.get(k) for k in ("pair_id", "code_type", "true_label")):
                    raise ValueError("Result sample identity conflicts with benchmark")
                expected_hash = digest(truth) if 'code' in truth else truth.get('sample_hash')
                if r.get('sample_hash') and expected_hash and r['sample_hash'] != expected_hash:
                    raise ValueError('Result input content conflicts with benchmark')
                if r.get('protocol') in ('corrected-v1', 'domain-cascade-v2', 'domain-cascade-v3', 'domain-cascade-v4') and 'raw_response' in r:
                    if parse_detection(r['raw_response'])['prediction'] != r['prediction']:
                        raise ValueError('Stored prediction conflicts with raw detector answer')
                    if not args.binary_only:
                        if r.get('judge_protocol') != JUDGE_PROTOCOL:
                            raise ValueError('Result does not use the supported Stage 2 judge protocol; rerun judging')
                        if r['prediction']:
                            if parse_judge(r.get('judge_rationale', ''), r['code_type']) != r.get('judge'):
                                raise ValueError('Stored judgment conflicts with raw judge answer')
                            judge_input = prepare_rationale(r['raw_response'])
                            expected_prompt = build_judge_prompt(truth['ground_truth'], judge_input, r['code_type'])
                            if r.get('judge_input') != judge_input or r.get('judge_prompt') != expected_prompt:
                                raise ValueError('Stored judge input conflicts with detector answer or benchmark evidence')
            hashes = {r.get('pipeline_hash') for r in result}
            if len(hashes) > 1:
                raise ValueError('Mixed pipeline identities; evaluate each run separately')
            emit(evaluate(result, by_id, require_judge=not args.binary_only), args.output)
        elif args.command == "normalize-nvd":
            emit(normalize_feeds(args.feeds, args.output))
        elif args.command == "index-nvd":
            emit(build_index(args.corpus, args.output))
        elif args.command == "query-nvd":
            n = NVDIndex(args.index, args.publication_metadata)
            emit(n.search(args.keywords, args.target_cve, args.before, args.top_k, args.max_frequency), args.output)
        elif args.command == "query-domain":
            n = NVDIndex(args.index, args.publication_metadata)
            emit(n.search_domain({'products': args.products, 'identifiers': args.identifiers,
                 'domain_terms': args.domain_terms}, repository=args.repository, target_cve=args.target_cve,
                 before=args.before, top_k=args.top_k, max_frequency=args.max_frequency), args.output)
        elif args.command == "prepare-primevul":
            _, manifest = convert_primevul(args.source, args.output, args.contexts)
            emit(manifest)
        elif args.command == 'prepare-sven':
            _, manifest = convert_sven(args.source, args.output)
            emit(manifest)
        elif args.command == "prepare-corpus":
            emit(filter_corpus(args.source, args.output, NVDIndex(args.index, args.publication_metadata), args.benchmark, args.before))
        elif args.command == "fetch-hf":
            import pyarrow.parquet as pq
            revision = "326d3b8970327977561fa79f2bc545f8f0b9339d"
            sha = "547a92376586cead9cff1ab63a817f6de8133d2464fd160ff871c9502785ee83"
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            url = f"https://huggingface.co/datasets/hzhu721/vulnerability-specifications/resolve/{revision}/data/train-00000-of-00001.parquet"
            with tempfile.TemporaryDirectory(prefix="vulinstruct-hf-") as temporary:
                source = Path(args.parquet) if args.parquet else Path(temporary) / "source.parquet"
                if not args.parquet:
                    urllib.request.urlretrieve(url, source)
                if file_digest(source) != sha:
                    raise ValueError("Pinned Hugging Face Parquet checksum mismatch")
                data = [r for r in pq.read_table(source).to_pylist() if r.get("split") == "train"]
            if not data:
                raise ValueError("No CORRECT training records in the pinned export")
            write_json(output, data)
            emit({"revision": revision, "rows": len(data), "split": "train", "sha256": sha, "url": url})
        elif args.command == "index-specs":
            from .retrieval import QwenEncoder, build_dense
            emit(build_dense(args.corpus, args.output, QwenEncoder(args.model, args.revision, args.device), args.include_code))
        elif args.command == "extract-kb":
            from .knowledge import build_knowledge
            config_path = Path(args.config).resolve()
            config = read_json(config_path)
            if config.get("cache_dir") and not Path(config["cache_dir"]).is_absolute():
                config["cache_dir"] = str(config_path.parent / config["cache_dir"])
            report = build_knowledge(args.source, args.output, make_client(config, args.max_calls, args.refresh_api_cache),
                                     config["models"]["knowledge"], args.limit, args.scope)
            emit(report)
            if report["failed"]:
                return 2
        elif args.command == "run":
            Path(args.output).mkdir(parents=True, exist_ok=True)
            for name in ('metrics.json', 'results.json', 'progress.json'):
                (Path(args.output) / name).unlink(missing_ok=True)
            from .pipeline import Pipeline
            from .retrieval import QwenEncoder, DenseIndex
            config = load_config(args.config)
            samples = select_samples(args.benchmark, args.pairs)
            # Check every selected input before loading weights or spending API calls.
            nvd = NVDIndex(config['nvd_index'], config.get('publication_metadata'))
            errors = check_samples(samples, nvd, config, not args.no_judge)
            if errors:
                emit({'data_ready': False, 'errors': errors, 'network_calls': 0})
                return 2
            emb = config.get("embedding", {})
            encoder = QwenEncoder(**emb)
            pipeline = Pipeline(make_client(config, args.max_calls, args.refresh_api_cache), DenseIndex(config["general_index"], encoder),
                                nvd, config)
            write_json(Path(args.output) / "benchmark-selection.json", samples)
            results = pipeline.run(samples, args.output, not args.no_judge, args.retry_errors)
            if any(r["status"] != "ok" for r in results):
                emit({"completed": sum(r["status"] == "ok" for r in results), "failed": sum(r["status"] != "ok" for r in results),
                      "message": "No aggregate metrics computed; resolve failures or resume explicitly"})
                return 2
            emit(evaluate(results, [s["sample_id"] for s in samples], require_judge=not args.no_judge), Path(args.output) / "metrics.json")
        elif args.command == 'preflight':
            report = preflight(args.benchmark, args.config, not args.no_judge, args.pairs)
            emit(report, args.output)
            if not report['data_ready']:
                return 2
        elif args.command == "doctor":
            root = Path(args.root)
            manifest_path = root / "data/MANIFEST.json"
            errors = []
            if manifest_path.exists():
                for entry in read_json(manifest_path)["files"]:
                    path = root / entry["path"]
                    if not path.exists() or file_digest(path) != entry["sha256"]:
                        errors.append(entry["path"])
            else:
                errors.append("data/MANIFEST.json is missing")
            emit({"python": sys.version.split()[0], "data_integrity_errors": errors,
                  "optional_packages": {n: bool(importlib.util.find_spec(n)) for n in ("numpy", "torch", "transformers", "pyarrow")},
                  "api_key_present": bool(os.environ.get("VULINSTRUCT_API_KEY")),
                  "offline_evaluation_requires_api": False})
            if errors:
                return 2
    except (ValueError, KeyError, OSError, RuntimeError, ImportError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
