"""Dense retrieval with verified feature identities and no silent zero vectors."""
import json
from pathlib import Path

from .io import digest, file_digest, read_json, write_json
from .nvd import timestamp


class QwenEncoder:
    def __init__(self, model="Qwen/Qwen3-Embedding-0.6B", revision=None, device=None, max_length=8192):
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError("Install vulinstruct-repro[embedding] for local Qwen embeddings") from exc
        self.torch = torch
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.max_length = max_length
        self.tokenizer = AutoTokenizer.from_pretrained(model, revision=revision, padding_side="left")
        self.model = AutoModel.from_pretrained(model, revision=revision).to(self.device).eval()
        resolved = getattr(self.model.config, "_commit_hash", None) or revision
        if Path(model).is_dir():
            files = sorted(p for p in Path(model).iterdir() if p.is_file() and
                           (p.suffix in ('.json', '.safetensors', '.bin', '.model', '.txt')))
            # A config alone cannot identify different weights of the same architecture.
            resolved = digest({p.name: file_digest(p) for p in files})
        self.identity = {"model": model, "revision": resolved, "pooling": "last-token/l2",
                         "max_length": max_length, "instruction": None}

    def encode(self, texts, batch_size=4):
        import numpy as np
        torch = self.torch
        vectors = []
        for start in range(0, len(texts), batch_size):
            chunk = texts[start:start + batch_size]
            if any(not isinstance(t, str) or not t.strip() for t in chunk):
                raise ValueError("Cannot embed an empty feature; never substitute a commit message or zero vector")
            tokens = self.tokenizer(chunk, padding=True, truncation=True,
                                    max_length=self.max_length, return_tensors="pt").to(self.device)
            with torch.no_grad():
                hidden = self.model(**tokens).last_hidden_state
                # Left padding guarantees the final token is real for every item.
                pooled = torch.nn.functional.normalize(hidden[:, -1], p=2, dim=1)
            vectors.append(pooled.cpu().float().numpy())
        return np.concatenate(vectors) if vectors else np.empty((0, 0), dtype="float32")


def unit_vectors(values):
    import numpy as np
    array = np.asarray(values, dtype=np.float32)
    if array.ndim != 2 or not np.isfinite(array).all():
        raise ValueError("Invalid embedding matrix")
    norms = np.linalg.norm(array, axis=1, keepdims=True)
    if (norms <= 1e-8).any():
        raise ValueError("Zero embedding detected; original embedding job failed")
    return array / norms


def build_dense(corpus_path, output, encoder, include_code=False):
    import numpy as np
    corpus = read_json(corpus_path)
    if not isinstance(corpus, list) or not corpus:
        raise ValueError("Expected non-empty normalized knowledge corpus")
    output = Path(output)
    if output.exists():
        raise FileExistsError("Choose a new index directory")
    features = ["understand", "code"] if include_code else ["understand"]
    matrices = {}
    for feature in features:
        if any(not r.get(feature, "").strip() for r in corpus):
            raise ValueError("Corpus has missing " + feature + "; HF export supports understand-only indexing")
        matrices[feature] = unit_vectors(encoder.encode([r[feature] for r in corpus]))
    output.mkdir(parents=True)
    np.savez_compressed(output / "vectors.npz", **matrices)
    write_json(output / "corpus.json", corpus)
    manifest = {"schema": "dense-v1", "encoder": encoder.identity, "features": features,
                "count": len(corpus), "corpus_sha256": file_digest(output / "corpus.json"),
                "vectors_sha256": file_digest(output / "vectors.npz"),
                "case_ids_hash": digest([r["case_id"] for r in corpus])}
    write_json(output / "manifest.json", manifest)
    return manifest


class DenseIndex:
    def __init__(self, directory, encoder):
        import numpy as np
        root = Path(directory)
        self.manifest = read_json(root / "manifest.json")
        self.corpus = read_json(root / "corpus.json")
        if file_digest(root / "corpus.json") != self.manifest["corpus_sha256"]:
            raise ValueError("Index corpus content hash mismatch")
        if file_digest(root / "vectors.npz") != self.manifest["vectors_sha256"]:
            raise ValueError("Index vectors content hash mismatch")
        if self.manifest["encoder"] != encoder.identity:
            raise ValueError("Index/query encoder identity differs; rebuild or use the recorded encoder")
        if digest([r["case_id"] for r in self.corpus]) != self.manifest["case_ids_hash"]:
            raise ValueError("Index metadata/case alignment mismatch")
        self.encoder = encoder
        with np.load(root / "vectors.npz", allow_pickle=False) as archive:
            self.vectors = {k: unit_vectors(archive[k]) for k in self.manifest["features"]}
        if any(len(m) != len(self.corpus) for m in self.vectors.values()):
            raise ValueError("Index row count mismatch")

    def search(self, understand, code, top_k=10, target_cve=None, before=None, exclude_commit=None):
        import numpy as np
        if top_k < 1:
            raise ValueError("top_k must be positive")
        texts = {"understand": understand, "code": code}
        weights = {"understand": .7, "code": .3} if "code" in self.vectors else {"understand": 1.0}
        scores = np.zeros(len(self.corpus))
        for feature, matrix in self.vectors.items():
            query = unit_vectors(self.encoder.encode([texts[feature]]))[0]
            if matrix.shape[1] != len(query):
                raise ValueError("Query embedding dimension mismatch")
            scores += weights[feature] * (matrix @ query)
        eligible = []
        for i, r in enumerate(self.corpus):
            if target_cve and r["cve_id"] == target_cve:
                continue
            if exclude_commit and r.get('commit_hash') == exclude_commit:
                continue
            if before and (not r.get("published") or timestamp(r["published"]) >= timestamp(before)):
                continue
            eligible.append(i)
        ranked = sorted(eligible, key=lambda i: (-float(scores[i]), self.corpus[i]["case_id"]))[:top_k]
        return [dict(self.corpus[i], similarity=float(scores[i])) for i in ranked]
