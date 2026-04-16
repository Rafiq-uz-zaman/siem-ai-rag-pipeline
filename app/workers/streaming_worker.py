import time
import logging
from app.config import settings

logger = logging.getLogger(__name__)

MAX_CHUNK_CHARS = 512


def _chunk_text(text: str, size: int = MAX_CHUNK_CHARS, overlap: int = 50):
    if len(text) <= size:
        return [text]
    chunks = []
    start = 0
    while start < len(text):
        chunks.append(text[start:min(start + size, len(text))])
        start += size - overlap
    return chunks


# ---------------------------------------------------------------------------
# Normalizers — one per source index
# ---------------------------------------------------------------------------

def _normalize_alert(hit) -> dict:
    """Wazuh alert → unified vector doc."""
    s = hit["_source"]
    message = (
        s.get("rule", {}).get("description")
        or s.get("full_log")
        or s.get("message")
        or ""
    )
    return {
        "source_type": "alerts",
        "@timestamp": s.get("@timestamp"),
        "rule_id": s.get("rule", {}).get("id"),
        "rule_description": s.get("rule", {}).get("description"),
        "rule_level": s.get("rule", {}).get("level"),
        "rule_groups": s.get("rule", {}).get("groups", []),
        "agent_id": s.get("agent", {}).get("id"),
        "agent_name": s.get("agent", {}).get("name"),
        "src_ip": s.get("data", {}).get("srcip"),
        "dest_ip": s.get("data", {}).get("dstip"),
        "severity": s.get("rule", {}).get("level"),
        "message": message,
    }


def _normalize_elastalert(hit) -> dict:
    """ElastAlert doc → unified vector doc."""
    s = hit["_source"]
    mb = s.get("match_body", {})
    ts = s.get("alert_time") or s.get("@timestamp")

    def _to_str(val):
        """Flatten dicts/lists to JSON string so ES text field never receives an object."""
        if val is None:
            return None
        if isinstance(val, (dict, list)):
            import json
            return json.dumps(val)
        return str(val)

    alert_description = _to_str(s.get("alert_description"))
    alert_info = _to_str(s.get("alert_info"))

    message = alert_description or alert_info or s.get("rule_name") or ""

    return {
        "source_type": "elastalert",
        "@timestamp": ts,
        "rule_name": s.get("rule_name"),
        "alert_type": s.get("alert_type"),
        "alert_description": alert_description,
        "alert_severity": (s.get("alert_severity") or "").lower() or None,
        "alert_info": alert_info,
        "agent_id": mb.get("agent", {}).get("id"),
        "agent_name": mb.get("agent", {}).get("name"),
        "message": message,
    }


def _normalize_vuln(hit) -> dict:
    """Wazuh vulnerability doc → unified vector doc."""
    s = hit["_source"]
    v = s.get("vulnerability", {})
    pkg = s.get("package", {})
    message = (
        v.get("description")
        or f"{v.get('id', '')} in {pkg.get('name', '')} {pkg.get('version', '')}".strip()
        or ""
    )
    ts = v.get("detected_at") or v.get("published_at") or s.get("@timestamp")
    return {
        "source_type": "vulnerabilities",
        "@timestamp": ts,
        "cve_id": v.get("id"),
        "vuln_severity": (v.get("severity") or "").lower() or None,
        "cvss_score": (v.get("score") or {}).get("base"),
        "vuln_description": v.get("description"),
        "package_name": pkg.get("name"),
        "package_version": pkg.get("version"),
        "host_os": s.get("host", {}).get("os", {}).get("name"),
        "agent_id": s.get("agent", {}).get("id"),
        "agent_name": s.get("agent", {}).get("name"),
        "message": message,
    }


# ---------------------------------------------------------------------------
# Generic poll-and-embed helper
# ---------------------------------------------------------------------------

def _poll_and_embed(es, embedder, index, normalizer, last_ts, label, time_field="@timestamp"):
    """
    Poll *index* for docs newer than *last_ts*, embed them, and bulk-index
    into the unified vector index.  Returns the new last_ts.
    """
    try:
        res = es.search(index, {
            "size": 500,
            "query": {"range": {time_field: {"gt": last_ts}}},
            "sort": [{time_field: "asc"}],
        })
    except Exception as e:
        logger.error(f"[{label}] Search error: {e}")
        return last_ts

    hits = res["hits"]["hits"]
    if not hits:
        return last_ts

    pairs = [(h, normalizer(h)) for h in hits]
    pairs = [(h, doc) for h, doc in pairs if doc.get("message")]
    if not pairs:
        # Navigate nested time_field (e.g. "vulnerability.detected_at")
        last_src = hits[-1]["_source"]
        parts = time_field.split(".")
        val = last_src
        for p in parts:
            val = val.get(p) if isinstance(val, dict) else None
        return val or last_ts

    expanded_hits, expanded_docs = [], []
    for hit, doc in pairs:
        for i, chunk in enumerate(_chunk_text(doc["message"])):
            expanded_hits.append(hit)
            expanded_docs.append({**doc, "message": chunk, "chunk_index": i})

    texts = [d["message"] for d in expanded_docs]
    embeddings = embedder.encode_batch(texts)

    actions = []
    for hit, doc, emb in zip(expanded_hits, expanded_docs, embeddings):
        doc["embedding"] = emb.tolist()
        ci = doc.get("chunk_index", 0)
        doc_id = f"{hit['_id']}_{ci}" if ci else hit["_id"]
        actions.append({"_index": settings.VECTOR_INDEX, "_id": doc_id, "_source": doc})

    es.bulk_index(actions)
    logger.info(f"[{label}] Embedded and indexed {len(actions)} docs.")

    # Extract last timestamp from raw hit using the time_field path
    last_src = hits[-1]["_source"]
    parts = time_field.split(".")
    val = last_src
    for p in parts:
        val = val.get(p) if isinstance(val, dict) else None
    return val or last_ts


# ---------------------------------------------------------------------------
# StreamingWorker
# ---------------------------------------------------------------------------

class StreamingWorker:

    def __init__(self):
        # Deferred imports so the module can be imported without elasticsearch installed
        # (the venv must be active when StreamingWorker is instantiated)
        from app.services.elasticsearch_service import ElasticsearchService
        from app.services.embedding_service import EmbeddingService
        self.es = ElasticsearchService()
        self.embedder = EmbeddingService()
        self._last_ts = {
            "alerts": "now-1h",
            "elastalert": "now-1h",
            "vulnerabilities": "now-1h",
        }

    def run(self):
        logger.info("Streaming worker started (alerts + elastalert + vulnerabilities).")
        while True:
            self._last_ts["alerts"] = _poll_and_embed(
                self.es, self.embedder,
                settings.ES_INDEX, _normalize_alert,
                self._last_ts["alerts"], "alerts",
                time_field="@timestamp"
            )
            self._last_ts["elastalert"] = _poll_and_embed(
                self.es, self.embedder,
                settings.ELASTALERT_INDEX, _normalize_elastalert,
                self._last_ts["elastalert"], "elastalert",
                time_field="alert_time"
            )
            self._last_ts["vulnerabilities"] = _poll_and_embed(
                self.es, self.embedder,
                settings.VULN_INDEX, _normalize_vuln,
                self._last_ts["vulnerabilities"], "vulnerabilities",
                time_field="vulnerability.detected_at"
            )
            time.sleep(settings.POLL_INTERVAL)