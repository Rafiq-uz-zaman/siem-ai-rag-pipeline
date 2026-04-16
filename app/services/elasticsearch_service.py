from elasticsearch import Elasticsearch, helpers, NotFoundError, BadRequestError
from tenacity import retry, stop_after_attempt, wait_fixed
from app.config import settings
import logging

logger = logging.getLogger(__name__)

VECTOR_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            # --- Shared across all sources ---
            "@timestamp":    {"type": "date"},
            "source_type":   {"type": "keyword"},   # "alerts" | "elastalert" | "vulnerabilities"
            "agent_id":      {"type": "keyword"},
            "agent_name":    {"type": "keyword"},
            "message":       {"type": "text"},
            "embedding": {
                "type": "dense_vector",
                "dims": 384,
                "index": True,
                "similarity": "cosine"
            },

            # --- Wazuh alerts ---
            "rule_id":          {"type": "keyword"},
            "rule_description": {"type": "text"},
            "rule_level":       {"type": "integer"},
            "rule_groups":      {"type": "keyword"},
            "src_ip":           {"type": "keyword"},
            "dest_ip":          {"type": "keyword"},
            "severity":         {"type": "integer"},  # mirrors rule_level for alerts

            # --- ElastAlert ---
            "rule_name":        {"type": "keyword"},
            "alert_type":       {"type": "keyword"},
            "alert_description": {"type": "text"},
            "alert_severity":   {"type": "keyword"},  # low | medium | high | critical
            "alert_info":       {"type": "text"},

            # --- Vulnerabilities ---
            "cve_id":           {"type": "keyword"},
            "vuln_severity":    {"type": "keyword"},  # low | medium | high | critical
            "cvss_score":       {"type": "float"},
            "package_name":     {"type": "keyword"},
            "package_version":  {"type": "keyword"},
            "vuln_description": {"type": "text"},
            "host_os":          {"type": "keyword"},
        }
    }
}


class ElasticsearchService:

    def __init__(self):
        self.client = Elasticsearch(
            settings.ES_HOST,
            verify_certs=False,
            ssl_show_warn=False,
            request_timeout=30,
        )

    def ensure_vector_index(self):
        """Create the vector index with dense_vector mapping if it doesn't exist."""
        try:
            # Attempt to create — if it already exists ES returns a 400 resource_already_exists_exception
            self.client.indices.create(
                index=settings.VECTOR_INDEX,
                mappings=VECTOR_INDEX_MAPPING["mappings"]
            )
            logger.info(f"Created index: {settings.VECTOR_INDEX}")
        except BadRequestError as e:
            if "resource_already_exists_exception" in str(e).lower():
                logger.info(f"Index already exists: {settings.VECTOR_INDEX}")
            else:
                logger.error(f"Failed to create vector index: {e}")
        except Exception as e:
            logger.error(f"Failed to ensure vector index: {e}")

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def search(self, index, body):
        return self.client.search(index=index, body=body)

    def bulk_index(self, actions):
        success, errors = helpers.bulk(self.client, actions, raise_on_error=False, stats_only=False)
        if errors:
            logger.warning(f"{len(errors)} document(s) failed to index. First error: {errors[0]}")

    def hybrid_search(self, query_vector, text_query, time_filter, k=10,
                      severity_min=None, severity_max=None,
                      source_types=None,
                      alert_severity=None,
                      vuln_severity=None):
        """
        Unified hybrid search across one or more source types.

        Parameters
        ----------
        source_types : list[str] | None
            e.g. ["alerts"], ["elastalert"], ["vulnerabilities"], or None / ["all"]
            for cross-index queries.
        severity_min / severity_max : int | None
            Applied to the `severity` (rule.level) field — wazuh alerts only.
        alert_severity : str | None
            e.g. "high" — filtered on `alert_severity` keyword field — elastalert only.
        vuln_severity : str | None
            e.g. "critical" — filtered on `vuln_severity` keyword field — vuln only.
        """
        filters = [{"range": {"@timestamp": time_filter}}]

        # Source type filter
        if source_types and "all" not in source_types:
            filters.append({"terms": {"source_type": source_types}})

        # Per-source severity filters
        if severity_min is not None or severity_max is not None:
            sev_range = {}
            if severity_min is not None:
                sev_range["gte"] = severity_min
            if severity_max is not None:
                sev_range["lte"] = severity_max
            filters.append({"range": {"severity": sev_range}})

        if alert_severity:
            filters.append({"term": {"alert_severity": alert_severity.lower()}})

        if vuln_severity:
            filters.append({"term": {"vuln_severity": vuln_severity.lower()}})

        num_candidates = max(k * 2, 100)

        try:
            return self.client.search(
                index=settings.VECTOR_INDEX,
                body={
                    "size": k,
                    "query": {
                        "bool": {
                            "filter": filters,
                            "must": [
                                {
                                    "multi_match": {
                                        "query": text_query,
                                        "fields": [
                                            "message^2",
                                            "rule_description^2",
                                            "alert_description^2",
                                            "vuln_description^2",
                                            "rule_id",
                                            "rule_name",
                                            "cve_id",
                                            "agent_name"
                                        ]
                                    }
                                }
                            ]
                        }
                    },
                    "knn": {
                        "field": "embedding",
                        "query_vector": query_vector,
                        "k": k,
                        "num_candidates": num_candidates,
                        "filter": filters
                    }
                }
            )
        except NotFoundError:
            logger.warning(f"Vector index '{settings.VECTOR_INDEX}' not found or empty. Returning empty result.")
            return {"hits": {"hits": []}}