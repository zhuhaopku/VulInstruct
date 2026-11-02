# Security and data handling

API credentials are read from the environment variable named in the configuration. Examples use a placeholder endpoint. Use an HTTPS service URL and keep credentials out of URLs and configuration files. The client rejects URL userinfo, query strings and fragments and refuses HTTP redirects. Loopback HTTP is supported for local model servers.

Model requests contain the selected target code, context and relevant knowledge. Review your provider's data handling terms before submitting source code. The framework treats benchmark code as input data and does not compile or execute it.

Runtime caches store requests, final responses, model identities, usage and hashes. These files can contain source code and evaluation evidence. Keep them in the ignored runtime directories. The transport does not cache the Authorization header or API key, and does not save provider reasoning text.

Cache identities include the relevant request, model, configuration, implementation and input data. The evaluator checks sample coverage and input consistency. Failed runs clear aggregate output files, while completed per-sample results can be resumed.

Before distributing a source package, run `tools/build_release.py` and check the resulting ZIP with `tools/audit_release.py`. The packaging tool uses an explicit file manifest. The scanner checks delivered text, nested ZIP/gzip contents, common credential patterns, private paths and prohibited runtime artifacts.

For security reports, contact the maintainers privately using the contact listed on the paper. Exclude working credentials and private source from public issues.
