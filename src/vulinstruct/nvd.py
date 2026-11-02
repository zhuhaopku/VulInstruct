"""NVD 1.1/2.0 normalization and indexed substring retrieval.

Retrieval policy: exclude rejected records, retain complete descriptions/CPEs,
filter by publication time AND numeric CVE order before keyword caps/ranking.
SQLite FTS5 trigrams accelerate exact substring semantics; a LIKE-independent
instr scan provides equivalent results on older SQLite builds.
"""
import json
import math
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from .io import digest, file_digest, read_json, rows, write_json, write_rows


def query_terms(values, products=False):
    """Grounded spelling/path variants; never infer a weakness or target CVE."""
    terms = []
    stop = {'none', 'src', 'lib', 'core', 'source', 'master', 'main', 'common', 'utils'}
    for value in values:
        if not isinstance(value, str):
            continue
        value = value.strip().lower().removesuffix('.git').rstrip('/')
        variants = [value]
        if '/' in value:
            variants.append(value.rsplit('/', 1)[-1])
        if products:
            # Repository names often carry a major version absent in NVD/CPE names.
            variants += [re.sub(r'[-_]?v?\d+$', '', v) for v in variants]
        for term in variants:
            if len(term) >= 3 and term not in stop and term not in terms:
                terms.append(term)
    return terms


def term_pattern(term):
    # property.c must not match mp4property.cpp; vim must not match pavim.
    return re.compile(r'(?<![a-z0-9_])' + re.escape(term) + r'(?![a-z0-9_])')


def cve_order(cve):
    m = re.fullmatch(r"CVE-(\d{4})-(\d+)", cve or "")
    if not m:
        raise ValueError("Invalid CVE identifier: " + str(cve))
    return tuple(map(int, m.groups()))


def timestamp(value):
    if not value:
        raise ValueError("Missing publication date; cannot certify historical eligibility")
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _walk_cpe(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("cpe23Uri", "criteria") and isinstance(item, str) and item.startswith("cpe:"):
                yield item
            elif isinstance(item, (dict, list)):
                yield from _walk_cpe(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_cpe(item)


def normalize(item):
    c = item.get("cve", item)
    cid = c.get("id", c.get("CVE_data_meta", {}).get("ID", ""))
    cve_order(cid)
    descriptions = c.get("descriptions", c.get("description", {}).get("description_data", []))
    description = "\n".join(x.get("value", "") for x in descriptions if x.get("lang", "en") == "en")
    rejected = (c.get("vulnStatus", "").lower() == "rejected"
                or "** REJECT **" in description.upper()
                or description.lstrip().lower().startswith("rejected reason:")
                or description.lstrip().upper().startswith("DO NOT USE THIS CANDIDATE NUMBER"))
    if rejected or not description.strip():
        return None
    published = c.get("published", item.get("publishedDate"))
    modified = c.get("lastModified", item.get("lastModifiedDate"))
    cpes = sorted(set(_walk_cpe(item)))
    weaknesses = c.get("weaknesses", c.get("problemtype", {}).get("problemtype_data", []))
    cwes = sorted({v.get("value") for w in weaknesses for v in w.get("description", []) if v.get("value", "").startswith("CWE-")})
    refs = c.get("references", [])
    if isinstance(refs, dict):
        refs = refs.get("reference_data", [])
    return {"cve_id": cid, "published": timestamp(published),
            "modified": timestamp(modified) if modified else None,
            "description": description, "cpes": cpes, "cwes": cwes,
            "references": sorted({r["url"] for r in refs if r.get("url")})}


def normalize_feeds(directory, output):
    records, rejected, duplicates, sources = {}, 0, 0, []
    for path in sorted(Path(directory).glob("nvdcve-*.json*")):
        data = read_json(path)
        items = data.get("CVE_Items", data.get("vulnerabilities"))
        if items is None:
            raise ValueError("Unknown NVD feed schema: " + str(path))
        sources.append({"file": path.name, "sha256": file_digest(path), "rows": len(items)})
        for item in items:
            record = normalize(item)
            if record is None:
                rejected += 1
                continue
            cid = record["cve_id"]
            if cid in records:
                duplicates += 1
                if (record["modified"] or "") < (records[cid]["modified"] or ""):
                    continue
            records[cid] = record
    if not sources:
        raise ValueError("No NVD feeds found")
    write_rows(output, (records[cid] for cid in sorted(records, key=cve_order)))
    manifest = {"schema": "normalized-nvd-v1", "count": len(records), "rejected_or_empty": rejected,
                "duplicates": duplicates, "sources": sources, "sha256": file_digest(output)}
    write_json(str(output) + ".manifest.json", manifest)
    return manifest


def build_index(corpus, output):
    output = Path(output)
    if output.exists():
        raise FileExistsError("Index already exists; choose a new output path")
    output.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(output)
    try:
        db.execute("CREATE TABLE cves (id INTEGER PRIMARY KEY, cve_id TEXT UNIQUE NOT NULL, year INT, seq INT, published TEXT NOT NULL, search TEXT NOT NULL, payload TEXT NOT NULL)")
        db.execute("CREATE INDEX temporal ON cves(published, year, seq)")
        db.execute("CREATE TABLE manifest (value TEXT NOT NULL)")
        count = 0
        for r in rows(corpus):
            year, seq = cve_order(r["cve_id"])
            published = timestamp(r["published"])
            search = (r["description"] + "\n" + "\n".join(r.get("cpes", []))).lower()
            db.execute("INSERT INTO cves(cve_id,year,seq,published,search,payload) VALUES (?,?,?,?,?,?)",
                       (r["cve_id"], year, seq, published, search, json.dumps(r, ensure_ascii=False)))
            count += 1
        if count == 0:
            raise ValueError("Empty NVD corpus")
        backend = "scan"
        try:
            db.execute("CREATE VIRTUAL TABLE search_fts USING fts5(search, content='cves', content_rowid='id', tokenize='trigram')")
            db.execute("INSERT INTO search_fts(search_fts) VALUES ('rebuild')")
            backend = "fts5-trigram"
        except sqlite3.OperationalError:
            db.execute("DROP TABLE IF EXISTS search_fts")
        manifest = {"schema": "nvd-sqlite-v1", "count": count, "backend": backend,
                    "corpus_sha256": file_digest(corpus), "sqlite": sqlite3.sqlite_version}
        db.execute("INSERT INTO manifest VALUES (?)", (json.dumps(manifest),))
        db.commit()
        return manifest
    except Exception:
        db.close()
        output.unlink(missing_ok=True)
        raise
    finally:
        db.close()


class NVDIndex:
    def __init__(self, path, publication_metadata=None):
        path = Path(path).resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        self._uri = path.as_uri() + '?mode=ro'
        self._local = threading.local()
        self.manifest = json.loads(self.db.execute("SELECT value FROM manifest").fetchone()[0])
        self.publication_metadata = read_json(publication_metadata) if publication_metadata else {}
        if publication_metadata:
            self.manifest["publication_metadata_sha256"] = file_digest(publication_metadata)

    @property
    def db(self):
        if not hasattr(self._local, 'connection'):
            self._local.connection = sqlite3.connect(self._uri, uri=True)
        return self._local.connection

    def close(self):
        if hasattr(self._local, 'connection'):
            self._local.connection.close()
            del self._local.connection

    def get(self, cve):
        result = self.db.execute("SELECT payload FROM cves WHERE cve_id=?", (cve,)).fetchone()
        if result:
            return json.loads(result[0])
        extra = self.publication_metadata.get("dates", {}).get(cve)
        return dict(extra, cve_id=cve, metadata_only=True) if extra else None

    def search_domain(self, query, repository='', target_cve=None, before=None,
                      top_k=10, max_frequency=500):
        """Product/component intersections first, then progressively broader evidence.

        Broad domain terms cannot flood the pool. Broad products are retained, and
        broad terms can still distinguish components *inside* that product pool.
        Eligibility is identical to search().
        """
        if top_k < 1 or max_frequency < 1:
            raise ValueError('top_k and max_frequency must be positive')
        if not before:
            target = self.get(target_cve) if target_cve else None
            if not target:
                raise ValueError('Target CVE publication is missing; pass explicit --before')
            before = target['published']
        before = timestamp(before)
        groups = {
            'product': query_terms([repository] + query.get('products', []), products=True),
            'identifier': query_terms(query.get('identifiers', [])),
            'domain': query_terms(query.get('domain_terms', [])),
        }
        # An identical product term must not masquerade as component evidence.
        groups['identifier'] = [t for t in groups['identifier'] if t not in groups['product']]
        groups['domain'] = [t for t in groups['domain'] if t not in groups['product'] + groups['identifier']]
        where, params = ['c.published < ?'], [before]
        if target_cve:
            year, seq = cve_order(target_cve)
            where.append('(c.year < ? OR (c.year = ? AND c.seq < ?))')
            params.extend([year, year, seq])
        pool, audits, frequencies = {}, [], {}
        patterns = {t: term_pattern(t) for terms in groups.values() for t in terms}
        for kind, terms in groups.items():
            for term in terms:
                clauses, args, join = list(where), list(params), ''
                if self.manifest['backend'] == 'fts5-trigram':
                    join = ' JOIN search_fts ON search_fts.rowid=c.id'
                    clauses.append('search_fts MATCH ?')
                    args.append('"' + term.replace('"', '""') + '"')
                clauses.append('instr(c.search, ?) > 0')
                args.append(term)
                sql = ('SELECT c.id,c.cve_id,c.published,c.search FROM cves c' + join
                       + ' WHERE ' + ' AND '.join(clauses))
                matches = []
                broad = False
                for row in self.db.execute(sql, args):
                    if patterns[term].search(row[3]):
                        matches.append(row)
                        if kind != 'product' and len(matches) > max_frequency:
                            broad = True
                            break
                frequencies[term] = len(matches)
                audits.append({'kind': kind, 'keyword': term, 'eligible_matches': len(matches),
                               'count_is_lower_bound': broad, 'global_pool_suppressed': broad,
                               'still_matched_inside_product_pool': broad})
                if not broad:
                    pool.update({r[0]: r for r in matches})
        ranked = []
        for row in pool.values():
            hits = {kind: [t for t in terms if patterns[t].search(row[3])]
                    for kind, terms in groups.items()}
            product, identifier, domain = (bool(hits[k]) for k in ('product', 'identifier', 'domain'))
            tier = (0 if product and identifier else 1 if product and domain else
                    2 if identifier else 3 if product else 4)
            # Historical v4's rarity principle, with explicit query intersection priority.
            terms = hits['identifier'] + hits['domain']
            rarity = sum(1 / math.log2(2 + frequencies[t]) for t in terms)
            components = {'query_rarity': rarity,
                          'attack': float('attack' in row[3]),
                          'length': min(len(row[3].split('\n', 1)[0]) / 500, 1),
                          'recency': min(max((int(row[2][:4]) - 2010) / 15, 0), 1)}
            score = .4 * rarity + .2 * sum(components[k] for k in ('attack', 'length', 'recency'))
            ranked.append((tier, -score, row[1], row[0], hits, components))
        ranked.sort(key=lambda r: r[:3])
        names = ['product_component', 'product_domain', 'component', 'product', 'domain']
        results = []
        for tier, neg_score, cid, rid, hits, components in ranked[:top_k]:
            record = json.loads(self.db.execute('SELECT payload FROM cves WHERE id=?', (rid,)).fetchone()[0])
            results.append(dict(record, matched_terms=hits, retrieval_tier=names[tier],
                                score=-neg_score, score_components=components))
        return {'results': results, 'audit': {
            'protocol': 'domain-cascade-v2', 'temporal': True, 'before': before,
            'target_cve': target_cve, 'max_frequency': max_frequency,
            'normalized_query': groups, 'keywords': audits, 'candidates': len(ranked),
            'corpus_sha256': self.manifest['corpus_sha256']}}

    def search(self, keywords, target_cve=None, before=None, top_k=10, max_frequency=500, temporal=True):
        if top_k < 1 or max_frequency < 1:
            raise ValueError("top_k and max_frequency must be positive")
        if temporal and not before:
            target = self.get(target_cve) if target_cve else None
            if target is None:
                raise ValueError("Target CVE publication is missing; pass explicit --before, never infer from year")
            before = target["published"]
        where, params = [], []
        if temporal:
            where.append("c.published < ?")
            params.append(timestamp(before))
            if target_cve:
                year, seq = cve_order(target_cve)
                where.append("(c.year < ? OR (c.year = ? AND c.seq < ?))")
                params.extend([year, year, seq])
        found, audit = {}, []
        for keyword in dict.fromkeys(k.strip().lower() for k in keywords if isinstance(k, str) and k.strip()):
            # Exact substring verification guarantees parity with the fallback scan.
            clauses, arguments = list(where), list(params)
            join = ""
            if self.manifest["backend"] == "fts5-trigram" and len(keyword) >= 3:
                join = " JOIN search_fts ON search_fts.rowid=c.id"
                clauses.append("search_fts MATCH ?")
                arguments.append('"' + keyword.replace('"', '""') + '"')
            clauses.append("instr(c.search, ?) > 0")
            arguments.append(keyword)
            sql = "SELECT c.payload FROM cves c" + join + " WHERE " + " AND ".join(clauses) + " LIMIT ?"
            matches = self.db.execute(sql, arguments + [max_frequency + 1]).fetchall()
            broad = len(matches) > max_frequency
            audit.append({"keyword": keyword, "eligible_matches": len(matches),
                          "count_is_lower_bound": broad, "discarded_as_broad": broad})
            if broad:
                continue
            for (payload,) in matches:
                record = json.loads(payload)
                cid = record["cve_id"]
                if cid not in found:
                    found[cid] = dict(record, matched_keywords=[])
                found[cid]["matched_keywords"].append(keyword)
        for r in found.values():
            # Explicit paper-description ranking, not the refactor's year-as-CVSS placeholder.
            components = {"attack": float("attack" in r["description"].lower()),
                          "length": min(len(r["description"]) / 500.0, 1.0),
                          "recency": min(max((int(r["published"][:4]) - 2010) / 15.0, 0.0), 1.0)}
            r["score_components"] = components
            r["score"] = sum(components.values()) / 3
        ranked = sorted(found.values(), key=lambda r: (-r["score"], r["cve_id"]))
        return {"results": ranked[:top_k], "audit": {"protocol": "corrected-paper-description-v1",
                "temporal": temporal, "target_cve": target_cve, "before": before,
                "max_frequency": max_frequency, "keywords": audit, "candidates": len(ranked),
                "corpus_sha256": self.manifest["corpus_sha256"]}}
