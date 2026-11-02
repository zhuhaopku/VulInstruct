# VulInstruct: Specification-Guided Vulnerability Detection

Specification-guided vulnerability detection using general security knowledge, domain-specific NVD evidence, and root-cause evaluation.

[Paper (FSE 2026)](https://doi.org/10.1145/3808132) | [Repository](https://github.com/zhuhaopku/VulInstruct) | [Knowledge dataset](https://huggingface.co/datasets/hzhu721/vulnerability-specifications)

## Updates

- **[2026/11/02]** Released the refactored VulInstruct implementation, with knowledge construction, retrieval, detection, root-cause evaluation, and bundled inputs for the paper's PrimeVul evaluation. The previous `exp/` outputs are preserved in [Previous VulInstruct evaluation](history/previous-vulinstruct-evaluation/).
- **[2026/03/28]** Our paper was accepted at **FSE 2026**. We shared experimental outputs in `exp/`, now available in [history](history/previous-vulinstruct-evaluation/).
- **[2026/01/21]** Released the VulInstruct **Specification Knowledge Base** on [Hugging Face](https://huggingface.co/datasets/hzhu721/vulnerability-specifications).

## Release background

At a very early stage of this work, we archived an initial implementation and experimental materials on [Zenodo (record 17211934)](https://zenodo.org/records/17211934). The implementation went through several revisions during paper submission and review. Corporate confidentiality constraints prevent us from publicly releasing one intermediate code version. This repository therefore provides a refactored implementation based on the initial Zenodo version and the method and evaluation updates in the final paper, organized to make VulInstruct easier to run, reuse, and extend.

**Start with the code and instructions in this repository.** The main evaluation uses the bundled inputs. The early Zenodo archive is retained for historical reference and is only needed for the optional workflow that extracts specifications again from the archived source inputs.

## Security specification library

Our **general security specification library is constructed from the CORRECT dataset**, introduced in [*Everything You Wanted to Know About LLM-based Vulnerability Detection But Were Afraid to Ask*](https://arxiv.org/abs/2504.13474). VulInstruct extracts security specifications and vulnerability/fix analyses from its vulnerable-patched code pairs. We publish the resulting specification library on [Hugging Face](https://huggingface.co/datasets/hzhu721/vulnerability-specifications). Domain-specific specifications use historical NVD evidence. In principle, the same extraction workflow can construct a security specification library from any high-quality vulnerability dataset that provides vulnerable and fixed code together with supporting vulnerability and patch evidence. See [knowledge construction](docs/DATA.md#extract-specifications-from-correct-dataset-inputs).

## Included data

This release contains the complete **PrimeVul evaluation dataset used in the paper**, with function code, available context, source identities and judge evidence. The bundled inputs are ready for the main evaluation.

It also includes 173,305 normalized historical NVD records, specifications derived from the CORRECT training split (`data/knowledge/correct-specifications.json`), the prepared retrieval corpus (`data/knowledge/correct-specifications-train.json`) and Qwen embedding index, and the SVEN benchmark. Data hashes and attribution are supplied in `data/MANIFEST.json` and `NOTICE`.

## Install and verify

Clone this repository, or extract the release archive, and use Python 3.9 or later:

```sh
git clone https://github.com/zhuhaopku/VulInstruct.git
cd VulInstruct
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
python -m vulinstruct doctor
python -m pytest -q
python tools/smoke_pipeline.py
```

These checks run without LLM requests. The smoke test uses synthetic responses; it is a software check, not a benchmark result.

## Run the full paper evaluation

```sh
python -m pip install -e '.[embedding]'
python -m vulinstruct index-nvd --corpus data/knowledge/nvd-2002-2024.jsonl.gz --output indexes/nvd.sqlite
cp examples/deepseek-flash.json examples/local-flash.json
```

Set your HTTPS model service URL and model aliases in `examples/local-flash.json`. Supply `VULINSTRUCT_API_KEY` through your environment. All three roles (knowledge, detector and judge) can use your DeepSeek Flash service. The shipped URL is a placeholder.

```sh
python -m vulinstruct preflight --benchmark data/benchmarks/primevul.jsonl.gz --config examples/local-flash.json
python -m vulinstruct run --benchmark data/benchmarks/primevul.jsonl.gz --config examples/local-flash.json --output runs/primevul-flash --max-calls 15000
python -m vulinstruct evaluate --results runs/primevul-flash/results.json --benchmark data/benchmarks/primevul.jsonl.gz --output runs/primevul-flash/verified-metrics.json
```

Omitting `--pairs` processes the **complete PrimeVul benchmark**. Preflight checks every sample and the retrieval data without API calls or loading model weights. Actual detection downloads the pinned Qwen query encoder on first use and calls the configured LLM service. Model weights are not included.

The explicit request cap includes retries; it is not a monetary budget or a guaranteed request count. For resume, service setup and output files, see [Running](docs/RUNNING.md).

## Documentation

| Guide | Contents |
|---|---|
| [Data](docs/DATA.md) | Bundled inputs, benchmark schema and knowledge preparation |
| [Running](docs/RUNNING.md) | Full evaluation, configuration, resume and troubleshooting |
| [Retrieval](docs/RETRIEVAL.md) | General embeddings and NVD selection |
| [Evaluation](docs/EVALUATION.md) | CORRECT Lenient decision table, before/after judging and metric interpretation |
| [Protocols](docs/PROTOCOLS.md) | Prompt versions, runtime settings and function pairs |

## Layout

| Directory | Contents |
|---|---|
| `history/previous-vulinstruct-evaluation/` | Previously published evaluation outputs |
| `data/benchmarks/` | Complete paper and SVEN evaluation inputs |
| `data/knowledge/` | CORRECT-derived specifications, NVD records and publication metadata |
| `data/prebuilt/` | Checked general knowledge vectors and encoder manifest |
| `src/vulinstruct/` | CLI and pipeline implementation |
| `tools/`, `tests/` | Preparation, packaging and validation |
| `examples/`, `docs/` | Configuration templates and instructions |

## License and citation

Author-owned code and documentation use the [MIT License](LICENSE). Included datasets and embedded source code retain their original terms; see [NOTICE](NOTICE) and `LICENSES/`. Model weights are obtained separately. If you use VulInstruct, please cite the [FSE 2026 paper](https://doi.org/10.1145/3808132). Machine-readable citation metadata is in [CITATION.cff](CITATION.cff).

```bibtex
@article{zhu2026vulinstruct,
  author  = {Hao Zhu and Jia Li and Cuiyun Gao and Jiaru Qian and Yihong Dong and Huanyu Liu and Lecheng Wang and Ziliang Wang and Xiaolong Hu and Ge Li},
  title   = {{VulInstruct}: Teaching {LLMs} Root-Cause Reasoning for Vulnerability Detection via Security Specifications},
  journal = {Proceedings of the ACM on Software Engineering},
  volume  = {3},
  number  = {FSE},
  pages   = {2813--2834},
  year    = {2026},
  doi     = {10.1145/3808132}
}
```
