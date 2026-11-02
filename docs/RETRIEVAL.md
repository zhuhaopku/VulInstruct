# Knowledge retrieval

The main workflow retrieves general knowledge and historical NVD cases, then scores their applicability to the target function. The configuration selects the index paths, embedding model, candidate count and relevance thresholds.

## General knowledge index

The default index uses Qwen3-Embedding-0.6B at revision `c54f2e6e80b2d7b7de06f51cec4959f6b3e03418`, with left padding, final-token pooling, L2 normalization and maximum input length 8192.

The `understand` field contains system identification and functional analysis. At query time, the LLM generates this description from the target code and available context. The default index and query encode their respective `understand` text, and candidates are ranked by cosine similarity.

A corpus that includes original code can use `index-specs --include-code`. This creates separate understanding and code vectors and combines their similarities as:

```text
similarity = 0.7 * cosine(understanding) + 0.3 * cosine(code)
```

Index manifests record the encoder identity, feature names, case ordering, corpus hash and vector hash. The query encoder must match the stored identity. Rebuild an index when changing its encoder or features. Missing input features, zero vectors and content mismatches raise errors.

Training preparation excludes test records and benchmark-overlap CVEs/available commits. Query-time filtering removes the target CVE/commit and cases published on or after the query cutoff. Default candidate count is 10.

## NVD preparation

Normalization retains full English descriptions, recursive CPE identifiers, CWE identifiers, references and dates. Explicit rejected records and empty descriptions are excluded. The SQLite index uses FTS5 trigrams where supported, with a scan fallback implementing the same matching rules.

Candidates must be published before the query cutoff. When a target CVE is supplied, their numeric `(year, sequence)` must also precede the target CVE. These constraints apply before candidate selection. A verified date is required.

## Domain cascade

The `domain-cascade-v4` pipeline extracts three query groups:

- Products and documented aliases.
- Component basenames or identifiers visible in the target.
- Short domain terms such as protocols, formats or subsystems.

Candidates are ranked by the following tiers: product with component, product with domain, component, product, and domain. Identifier matching uses component boundaries. Product pools are retained; identifier/domain terms exceeding the frequency cap cannot independently expand the global pool, but may match within a product pool. The default cap is 500 eligible records.

Within a tier, the score combines matched-term rarity, attacker-related text, description length and recency. Results include matched terms, tier, score components, candidate counts and temporal metadata. Use the query command to inspect them:

```sh
python -m vulinstruct query-domain --index indexes/nvd.sqlite --publication-metadata data/knowledge/publication-dates.json --repository ImageMagick6 --identifiers magick/property.c --domain-terms EXIF --target-cve CVE-2022-32547 --output runs/nvd-query.json
```

`query-nvd` provides the flat substring-search interface used by the `corrected-v1` protocol. `query-domain` provides the grouped cascade used by subsequent protocols. Exact protocol names are retained in saved results.

## Applicability and specifications

General cases, general HS specifications and NVD cases receive independent integer applicability scores from 1 to 10. The default inclusion threshold is 6 for each channel. Scores must cover every supplied candidate identity. Applicable specifications can be retained even when a detailed case is excluded.

When at least two NVD cases pass selection, the model can derive recurring AS specifications. Each specification must cite at least two distinct selected CVEs. An empty specification list is valid when no supported recurring pattern is found.

The selected cases, general specifications, NVD descriptions and domain specifications are supplied to the detector together with the target code and context. Detailed case text includes understanding, specifications, vulnerability analysis and solution analysis. Retrieval metadata remains available in the result trace.
