"""Build general specifications from CORRECT-format vulnerable/fixed patches."""
import re
from pathlib import Path

from .extraction_prompts import generate_context_model_prompt, generate_threat_model_prompt
from .io import digest, read_json, write_json


def tag(text, name):
    found = re.findall(r"<" + name + r">(.*?)</" + name + r">", text, re.S)
    if len(found) != 1 or not found[0].strip():
        raise ValueError("Missing/ambiguous extraction field: " + name)
    return found[0].strip()


def build_knowledge(source, output, client, model, limit=None, scope="all-methods"):
    if limit is not None and limit < 1:
        raise ValueError('limit must be positive')
    raw = read_json(source)
    if not isinstance(raw, list) or not raw:
        raise ValueError("Expected a non-empty CORRECT-format JSON list")
    if scope not in ("all-methods", "legacy-first-method"):
        raise ValueError("Unknown extraction scope")
    cases, failed = [], []
    for item in raw[:limit] if limit else raw:
        cid = item["cve_id"]
        try:
            before = item.get("vulnerableMethods_before", [])
            after = item.get("vulnerableMethods_after", [])
            if scope == "legacy-first-method":
                before, after = before[:1], after[:1]
            if not before or not after:
                raise ValueError("Missing before/after methods")
            vuln = "\n\n".join(m["raw_code"] for m in before)
            fixed = "\n\n".join(m["raw_code"] for m in after)
            case_id = cid + "_" + item["commit_hash"][:12] + "_" + digest([vuln, fixed])[:8]
            args = {"commit_message": item.get("commit_msg", ""), "cve_description": str(item.get("cve_desc", "")),
                    "cwe_type": ",".join(item.get("cwe_list", [])), "code_context": item.get("code_context", ""),
                    "vuln": vuln, "fixed": fixed}
            if not args["cve_description"] or not args["commit_message"]:
                raise ValueError("Missing patch evidence")
            first = client.ask(generate_threat_model_prompt(repository=item["repository"], **args), model, "extract-general-specifications")
            understand = tag(first, "understand")
            specifications = [s.strip() for s in re.findall(r"<spec>(.*?)</spec>", first, re.S) if s.strip()]
            if not specifications:
                raise ValueError("No general specifications extracted")
            second = client.ask(generate_context_model_prompt(understand=understand, specification="\n".join(specifications), **args), model, "extract-case-analysis")
            cases.append({"case_id": case_id, "cve_id": cid, "commit_hash": item["commit_hash"],
                          "repository": item["repository"], "understand": understand, "specifications": specifications,
                          "threat_model": tag(second, "model"), "vulnerability_analysis": tag(second, "vuln"),
                          "solution_analysis": tag(second, "solution"), "code": vuln, "split": "train",
                          "extraction_scope": scope, "model": model,
                          "source_hash": digest(item), "raw_extraction": [first, second]})
        except Exception as exc:
            failed.append({"cve_id": cid, "commit": item.get("commit_hash"), "error": str(exc)})
        # Partial progress is an explicit checkpoint, not a successful full corpus.
        write_json(output, cases)
        write_json(str(output) + ".manifest.json", {"processed": len(cases) + len(failed), "successful": len(cases),
                   "failed": failed, "scope": scope, "complete": len(cases) + len(failed) == min(limit or len(raw), len(raw)) and not failed})
    return {"successful": len(cases), "failed": failed}
