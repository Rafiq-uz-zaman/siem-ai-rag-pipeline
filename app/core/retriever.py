# from app.core.correlation import correlate_alerts
# from app.core.anomaly_detection import detect_spike

# class Retriever:

#     def __init__(self, es_service, embedding_service):
#         self.es = es_service
#         self.embedder = embedding_service

#     def retrieve(self, query, time_filter):
#         vector = self.embedder.encode_query(query)

#         res = self.es.hybrid_search(
#             query_vector=vector.tolist(),
#             text_query=query,
#             time_filter=time_filter
#         )

#         hits = res["hits"]["hits"]

#         alerts = [h["_source"] for h in hits]

#         correlated = correlate_alerts(alerts)

#         return {
#             "alerts": alerts,
#             "correlation": correlated
#         }







from app.core.correlation import correlate_alerts
from app.core.anomaly_detection import detect_spike
import re
from collections import Counter


def _extract_severity_range(query: str):
    """
    Parse severity/level range from natural language.
    Only meaningful for Wazuh alerts (integer rule.level scale 1-15).
    Examples:
      'severity between 6 to 8'  → (6, 8)
      'severity 10'              → (10, 10)
      'level 6-8'               → (6, 8)
      'above severity 7'        → (7, None)  -- 7 and higher
    Returns (min, max) or (None, None) if not found.
    """
    q = query.lower()

    # "between X to/and Y" or "X to Y" or "X-Y"
    m = re.search(r'(?:between\s+)?(\d+)\s*(?:to|and|-)\s*(\d+)', q)
    if m and any(w in q for w in ("severity", "level", "rule.level")):
        return int(m.group(1)), int(m.group(2))

    # "above/greater than X"
    m = re.search(r'(?:above|greater than|higher than|>=?)\s*(?:severity|level)?\s*(\d+)', q)
    if m:
        return int(m.group(1)), None

    # "below/less than X"
    m = re.search(r'(?:below|less than|lower than|<=?)\s*(?:severity|level)?\s*(\d+)', q)
    if m:
        return None, int(m.group(1))

    # "severity X" (single value)
    m = re.search(r'(?:severity|level)\s+(\d+)', q)
    if m:
        v = int(m.group(1))
        return v, v

    return None, None


# String severity words used by ElastAlert and Vulnerabilities
_STRING_SEVERITIES = {"low", "medium", "high", "critical"}


def _extract_string_severity(query: str):
    """
    Extract a string severity keyword for ElastAlert / Vulnerability indices.
    Returns e.g. 'high', 'critical', or None.
    """
    q = query.lower()
    for s in ("critical", "high", "medium", "low"):
        if s in q:
            return s
    return None


class Retriever:

    def __init__(self, es, embedder):
        self.es = es
        self.embedder = embedder

    def retrieve(self, query, time_filter, size=10, source="alerts"):
        """
        Parameters
        ----------
        source : str
            "alerts" | "elastalert" | "vulnerabilities" | "all"
        """
        vector = self.embedder.encode_query(query)

        # Resolve source_types list for the ES call
        if source == "all":
            source_types = ["alerts", "elastalert", "vulnerabilities"]
        else:
            source_types = [source]

        # Per-source severity extraction
        sev_min, sev_max = None, None
        alert_severity = None
        vuln_severity = None

        if source in ("alerts", "all"):
            sev_min, sev_max = _extract_severity_range(query)

        if source in ("elastalert", "all"):
            alert_severity = _extract_string_severity(query)

        if source in ("vulnerabilities", "all"):
            vuln_severity = _extract_string_severity(query)

        res = self.es.hybrid_search(
            vector.tolist(), query, time_filter,
            k=size,
            source_types=source_types,
            severity_min=sev_min,
            severity_max=sev_max,
            alert_severity=alert_severity,
            vuln_severity=vuln_severity,
        )

        hits = [h["_source"] for h in res["hits"]["hits"]]

        # Tag each hit with its source_type for client clarity
        result = {
            "source": source,
            "hits": hits,
            "total": len(hits),
        }

        # Alerts-specific enrichment
        if source in ("alerts", "all"):
            sev_counts = Counter(
                h.get("severity") for h in hits
                if h.get("source_type") == "alerts" and h.get("severity") is not None
            )
            result["severity_summary"] = [
                {"level": lvl, "count": cnt}
                for lvl, cnt in sorted(sev_counts.items())
            ]

            alert_hits = [h for h in hits if h.get("source_type", "alerts") == "alerts"]
            correlation = correlate_alerts(alert_hits)
            ip_counts = {ip: len(al) for ip, al in correlation.items()}
            avg_count = (sum(ip_counts.values()) / len(ip_counts)) if ip_counts else 0
            result["correlation"] = correlation
            result["anomalous_ips"] = [
                {"ip": ip, "count": cnt, "spike": True}
                for ip, cnt in ip_counts.items()
                if detect_spike(cnt, avg_count)
            ]

        # Record applied severity filters
        filters_applied = {}
        if sev_min is not None or sev_max is not None:
            filters_applied["rule_level"] = {"min": sev_min, "max": sev_max}
        if alert_severity:
            filters_applied["alert_severity"] = alert_severity
        if vuln_severity:
            filters_applied["vuln_severity"] = vuln_severity
        if filters_applied:
            result["severity_filters_applied"] = filters_applied

        return result