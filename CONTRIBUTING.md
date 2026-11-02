# Contributing

Use English for author-owned code comments, docstrings, documentation and configuration examples. Preserve upstream source code and dataset text verbatim. Bundled inputs are pinned in `data/MANIFEST.json`; record any intentional data revision explicitly.

```sh
python -m pytest -q
python tools/smoke_pipeline.py
python -m vulinstruct doctor
```

Keep credentials, local service configurations, model weights and runtime outputs outside releases. Update the explicit release allowlist after reviewing a change. Build with `python tools/build_release.py --output /path/to/new-release.zip` and retain the checksum. Dataset scan exceptions are restricted to reviewed, hash-pinned external content.
