"""
Bulk Backfill Script
====================
Reads existing docs from one or all source indices, generates embeddings,
and indexes them into the unified vector index (wazuh-alerts-vector).

Run from project root (C:\\siem\\SIEM-RAG-PIPELINE):

    # Backfill everything (all three sources, last 30 days)
    python -m app.scripts.backfill

    # Specific source and time range
    python -m app.scripts.backfill --source alerts --since "now-7d"
    python -m app.scripts.backfill --source vulnerabilities --since "now-90d"
    python -m app.scripts.backfill --source elastalert --since "2026-01-01T00:00:00"
"""

import argparse
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

MAX_CHUNK_CHARS = 512


def _chunk_text(text: str, size: int = MAX_CHUNK_CHARS, overlap: int = 50):
    if len(text) <= size:
        return [text]
    chunks, start = [], 0
    while start < len(text):
        chunks.append(text[start:min(start + size, len(text))])
        start += size - overlap
    return chunks


# ---------------------------------------------------------------------------
# Per-source normalizers (mirror streaming_worker.py)
# ---------------------------------------------------------------------------

def _normalize_alert(hit) -> dict:
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
    s = hit["_source"]
    mb = s.get("match_body", {})
    ts = s.get("alert_time") or s.get("@timestamp")

    def _to_str(val):
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


NORMALIZERS = {
    "alerts":          _normalize_alert,
    "elastalert":      _normalize_elastalert,
    "vulnerabilities": _normalize_vuln,
}


# ---------------------------------------------------------------------------
# Core backfill logic
# ---------------------------------------------------------------------------

def _process_batch(hits, normalizer, embedder, es, settings) -> int:
    pairs = [(h, normalizer(h)) for h in hits]
    pairs = [(h, doc) for h, doc in pairs if doc.get("message")]
    if not pairs:
        return 0

    expanded_hits, expanded_docs = [], []
    for hit, doc in pairs:
        chunks = _chunk_text(doc["message"])
        if len(chunks) == 1:
            expanded_hits.append(hit)
            expanded_docs.append({**doc, "chunk_index": 0})
        else:
            for i, chunk in enumerate(chunks):
                expanded_hits.append(hit)
                expanded_docs.append({**doc, "message": chunk, "chunk_index": i})

    texts = [d["message"] for d in expanded_docs]
    try:
        embeddings = embedder.encode_batch(texts)
    except Exception as e:
        logger.error(f"Embedding error: {e}")
        return 0

    actions = []
    for hit, doc, emb in zip(expanded_hits, expanded_docs, embeddings):
        doc["embedding"] = emb.tolist()
        ci = doc.get("chunk_index", 0)
        doc_id = f"{hit['_id']}_{ci}" if ci else hit["_id"]
        actions.append({"_index": settings.VECTOR_INDEX, "_id": doc_id, "_source": doc})

    try:
        es.bulk_index(actions)
        logger.info(f"Indexed {len(actions)} docs")
        return len(actions)
    except Exception as e:
        logger.error(f"Bulk index error: {e}")
        return 0


def _backfill_index(source_name, source_index, normalizer, since, batch_size, es, embedder, settings,
                    time_query=None, sort_fields=None):
    """PIT-paginate source_index and embed everything since `since`."""
    logger.info(f"--- Backfilling [{source_name}] from {source_index} (since {since}) ---")

    if time_query is None:
        time_query = {"range": {"@timestamp": {"gte": since}}}
    if sort_fields is None:
        sort_fields = [{"@timestamp": "asc"}, {"_shard_doc": "asc"}]

    total = 0
    pit = None

    try:
        pit_resp = es.client.open_point_in_time(index=source_index, keep_alive="5m")
        pit = pit_resp["id"]
    except Exception as e:
        logger.warning(f"PIT unavailable ({e}); falling back to scroll.")

    if pit:
        search_after = None
        while True:
            body = {
                "size": batch_size,
                "query": time_query,
                "sort": sort_fields,
                "pit": {"id": pit, "keep_alive": "5m"},
            }
            if search_after:
                body["search_after"] = search_after
            try:
                res = es.client.search(body=body)
            except Exception as e:
                logger.error(f"Search error: {e}")
                break
            hits = res["hits"]["hits"]
            if not hits:
                break
            pit = res["pit_id"]
            search_after = hits[-1]["sort"]
            total += _process_batch(hits, normalizer, embedder, es, settings)
        try:
            es.client.close_point_in_time(body={"id": pit})
        except Exception:
            pass
    else:
        try:
            res = es.client.search(
                index=source_index, scroll="2m",
                body={"size": batch_size, "query": time_query, "sort": sort_fields}
            )
            scroll_id = res["_scroll_id"]
            while True:
                hits = res["hits"]["hits"]
                if not hits:
                    break
                total += _process_batch(hits, normalizer, embedder, es, settings)
                res = es.client.scroll(scroll_id=scroll_id, scroll="2m")
            es.client.clear_scroll(scroll_id=scroll_id)
        except Exception as e:
            logger.error(f"Scroll error: {e}")

    logger.info(f"[{source_name}] Backfill complete — total indexed: {total}")
    return total


def main(since: str = "now-30d", batch_size: int = 200, source: str = "all"):
    from app.services.elasticsearch_service import ElasticsearchService
    from app.services.embedding_service import EmbeddingService
    from app.config import settings

    es = ElasticsearchService()
    embedder = EmbeddingService()
    es.ensure_vector_index()

    index_map = {
        "alerts":          settings.ES_INDEX,
        "elastalert":      settings.ELASTALERT_INDEX,
        "vulnerabilities": settings.VULN_INDEX,
    }

    targets = list(index_map.keys()) if source == "all" else [source]

    # Per-source time queries and sort strategies
    # - alerts: @timestamp exists, use standard range + _shard_doc tiebreaker
    # - elastalert: may use alert_time or @timestamp, sort by _shard_doc only
    # - vulnerabilities: state index with no @timestamp, use match_all + _shard_doc
    source_time_queries = {
        "alerts": {"range": {"@timestamp": {"gte": since}}},
        "elastalert": {
            "bool": {
                "should": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"range": {"alert_time": {"gte": since}}},
                ],
                "minimum_should_match": 1,
            }
        },
        "vulnerabilities": {"match_all": {}},  # state index — no reliable timestamp
    }
    source_sorts = {
        "alerts":          [{"@timestamp": "asc"}, {"_shard_doc": "asc"}],
        "elastalert":      [{"_shard_doc": "asc"}],
        "vulnerabilities": [{"_shard_doc": "asc"}],
    }

    grand_total = 0
    for target in targets:
        grand_total += _backfill_index(
            source_name=target,
            source_index=index_map[target],
            normalizer=NORMALIZERS[target],
            since=since,
            batch_size=batch_size,
            es=es,
            embedder=embedder,
            settings=settings,
            time_query=source_time_queries[target],
            sort_fields=source_sorts[target],
        )

    logger.info(f"All backfills done. Grand total indexed: {grand_total}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backfill source indices into unified vector index")
    parser.add_argument(
        "--source",
        choices=["all", "alerts", "elastalert", "vulnerabilities"],
        default="all",
        help="Which source index to backfill (default: all)"
    )
    parser.add_argument("--since", default="now-30d", help="Time range start (ES date math or ISO)")
    parser.add_argument("--batch-size", type=int, default=200, help="Docs per batch")
    args = parser.parse_args()
    main(since=args.since, batch_size=args.batch_size, source=args.source)
