# Data included in the release

The archive includes the complete PrimeVul benchmark and retrieval inputs used by the documented evaluation workflow.

| Path | Contents |
|---|---|
| `data/benchmarks/primevul.jsonl.gz` | Complete PrimeVul evaluation set used in the paper |
| `data/knowledge/nvd-2002-2024.jsonl.gz` | 173,305 normalized historical NVD records |
| `data/knowledge/nvd-2002-2024.jsonl.gz.manifest.json` | Feed filenames, hashes and normalization counts |
| `data/knowledge/publication-dates.json` | Supplemental CVE publication metadata |
| `data/knowledge/correct-specifications.json` | 1,491 specification and case-analysis records extracted from the CORRECT training split, distributed through HF |
| `data/knowledge/correct-specifications-train.json` | 1,452 prepared CORRECT-derived training records for general retrieval |
| `data/knowledge/correct-specifications-train.json.manifest.json` | Corpus preparation counts and exclusions |
| `data/prebuilt/qwen-general/` | Corpus, numeric vectors and pinned encoder manifest |
| `data/benchmarks/sven-844.jsonl.gz` | Additional SVEN benchmark: 844 C/C++ functions, 422 pairs |

`data/MANIFEST.json` pins each distributed data file by size and SHA-256. Verify the complete archive after extraction:

```sh
python -m vulinstruct doctor
```

## PrimeVul benchmark

`data/benchmarks/primevul.jsonl.gz` contains the PrimeVul evaluation set used in the paper and is ready for the main pipeline. Each record includes its function code, available context, source identity, pair identity, label and ground-truth evidence. No additional source archive is required.

Pairing uses function identities, so separate functions associated with the same CVE remain separate pairs. All paper samples are retained. Available context is preserved; otherwise the context field is empty.

General detection uses the target repository, filename, code and context. CVE descriptions, fixing messages and paired diffs are supplied to the judge. See [Protocols](PROTOCOLS.md) for the evaluation rules and the [PrimeVul project](https://github.com/DLVulDet/PrimeVul) for upstream data and attribution.

## Included NVD snapshot

The included corpus is normalized from the archived feeds named 2002 through 2024. Those files contain 188,461 input records; normalization excludes 15,156 rejected or empty-description records, leaving 173,305 searchable records. This is the pinned historical collection used by this release, not a promise of complete current NVD coverage.

Descriptions, publication timestamps, CPEs, references and source hashes are retained. Build the local search index directly from the included compressed corpus:

```sh
python -m vulinstruct index-nvd --corpus data/knowledge/nvd-2002-2024.jsonl.gz --output indexes/nvd.sqlite
```

There is no online NVD dependency for the main run. To use a different snapshot, follow the optional preparation workflow below and record the new manifest.

## Specification library built from the CORRECT dataset

The general security specification library is constructed from the **CORRECT dataset** introduced in [*Everything You Wanted to Know About LLM-based Vulnerability Detection But Were Afraid to Ask*](https://arxiv.org/abs/2504.13474). Its vulnerable-patched code pairs, vulnerability descriptions, fixing messages and available context provide the inputs for extracting general HS specifications and vulnerability/fix analyses.

To construct the retrieval corpus, we split CORRECT at **2020-01-01 (UTC)** using fixing-commit committer dates, retain the earlier records as the training split, and remove cases whose CVE IDs appear in the PrimeVul test set.

Our extracted library is published as the [vulnerability-specifications dataset](https://huggingface.co/datasets/hzhu721/vulnerability-specifications). The bundled CORRECT specification files contain these extracted specifications, system/function descriptions and case analyses. The export uses HF revision `326d3b8970327977561fa79f2bc545f8f0b9339d` and verifies the Parquet SHA-256 `547a92376586cead9cff1ab63a817f6de8133d2464fd160ff871c9502785ee83`.

```sh
python -m pip install -e '.[data,embedding]'
python -m vulinstruct fetch-hf --output research-data/correct-specifications.json
```

The bundled `data/knowledge/correct-specifications.json` and the `fetch-hf` command retain only records whose row-level `split` is `train`. The prepared retrieval corpus, `data/knowledge/correct-specifications-train.json`, contains 1,452 cases. Use `prepare-corpus` and rebuild vectors when preparing a corpus for a different benchmark.

The HF export provides the `understand` field, containing system identification and functional analysis. The default general index embeds this field. Raw-code indexing is also available for a corpus containing a non-empty `code` field; see [retrieval](RETRIEVAL.md).

## NVD feeds and a new index

Download JSON or JSON.gz feeds from the [official NVD data feeds](https://nvd.nist.gov/vuln/data-feeds) into `research-data/nvd-feeds/`. NVD 1.1 and 2.0 schemas are supported.

```sh
python -m vulinstruct normalize-nvd --feeds research-data/nvd-feeds --output research-data/nvd.jsonl.gz
python -m vulinstruct index-nvd --corpus research-data/nvd.jsonl.gz --output indexes/current-nvd.sqlite
python -m vulinstruct prepare-corpus --source research-data/correct-specifications.json --benchmark research-data/my-benchmark.jsonl --index indexes/current-nvd.sqlite --output research-data/correct-specifications-train.json
python -m vulinstruct index-specs --corpus research-data/correct-specifications-train.json --output indexes/general
```

Prepare `my-benchmark.jsonl` using the schema below before filtering the corpus. If a snapshot omits a needed CVE date, supply verified supplemental metadata using `--publication-metadata`. Inspect the preparation manifest for exclusion counts, including missing dates. `--before` sets an optional global cutoff; individual queries also apply their own publication cutoff.

Keep source URLs, acquisition dates and feed hashes with each experiment. Set the resulting corpus/index paths in your local model configuration.

## Extract specifications from CORRECT dataset inputs

The extraction workflow can also be applied to other high-quality vulnerability datasets. Supply vulnerable and fixed code, vulnerability descriptions, patch evidence and available context in the supported input schema, then prepare and index the extracted specifications.

The CORRECT source inputs used for knowledge construction are included in `VulInstruct.zip` from [Zenodo record 17211934](https://zenodo.org/records/17211934). The extraction helper checks the published MD5 and exports `correct-dataset-train.json`, `correct-specifications-archive.json` and `primevul-contexts.json`:

```sh
python tools/extract_zenodo.py --zip VulInstruct.zip --output research-data/zenodo-inputs
python -m vulinstruct extract-kb --source research-data/zenodo-inputs/correct-dataset-train.json --config examples/local-flash.json --output research-data/correct-specifications-extracted.json --limit 1 --max-calls 4
```

Configure the model service as described in [Running](RUNNING.md). Each input record supplies vulnerable and fixed methods, repository, commit, CVE description, fixing message and available context. Extraction produces general HS specifications and case analyses. The default processes all supplied methods; `--scope legacy-first-method` selects the first method on each side.

Run `prepare-corpus` on the extracted output before indexing. Use `index-specs --include-code` when selecting the dual-feature index. NVD feeds are acquired separately for this workflow.

## Benchmark schema

Each JSON/JSONL record contains:

| Field | Meaning |
|---|---|
| `sample_id` | Unique function-sample identity |
| `pair_id` | Shared identity of a vulnerable/fixed function pair |
| `code_type` | `before` or `after` |
| `true_label` | 1 for `before`, 0 for `after` |
| `repository`, `filename` | Target project and source file |
| `code`, `context` | Target function and available source context |
| `cve_id`, `commit_hash` | Source identifiers when available |
| `published` | Verified cutoff date, or use a resolvable CVE date |
| `ground_truth_status` | Evidence status used by evaluation |
| `ground_truth` | CVE description, fixing message and exact paired function diff |

`ground_truth` contains `cve_description`, `commit_message` and `code_diff` for root-cause judging. These fields are supplied to the judge. Target understanding, retrieval scoring and detection use repository, filename, code and context.

The converter commands are:

```sh
python -m vulinstruct prepare-primevul --source INPUT --contexts CONTEXTS --output OUTPUT
python -m vulinstruct prepare-sven --source INPUT --output OUTPUT
```

They validate supported source schemas and create canonical identities. `requires_review` records require evidence resolution before fresh judging. SVEN's `patch_only` evidence uses an explicit cutoff and `allow_patch_only_judge: true`. An empty function diff requires additional evidence for fresh judging. Missing context remains an empty field with an accompanying context status.

`tools/smoke_pipeline.py --output runs/synthetic-example` generates a complete synthetic benchmark and intermediate artifacts for inspecting the schema.

## Data terms

CORRECT, the HF specification library, PrimeVul, SVEN, NVD and model sources retain their own terms and attribution. See [NOTICE](../NOTICE) for source links. Keep the bundled bytes and manifests when comparing runs.
