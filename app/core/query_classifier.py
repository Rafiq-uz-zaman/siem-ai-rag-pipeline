class QueryClassifier:

    AGG_KEYWORDS = ["top", "count", "average", "sum"]
    # 'above' removed — conflicts with 'above severity 7' which is a filter query, not a follow-up
    FOLLOW_UP = ["previous result", "those alerts", "from above results"]

    # Keywords that signal a specific source index
    _VULN_KEYWORDS = [
        "cve", "vulnerability", "vulnerabilities", "cvss", "patch",
        "package", "exploit", "outdated", "unpatched"
    ]
    _ELASTALERT_KEYWORDS = [
        "elastalert", "rule fired", "alert rule", "triggered rule",
        "correlation rule", "alert triggered", "rule matched"
    ]

    def classify(self, query: str) -> str:
        q = query.lower()

        if any(k in q for k in self.FOLLOW_UP):
            return "follow_up"

        if any(k in q for k in self.AGG_KEYWORDS):
            return "aggregation"

        if "similar" in q or "like" in q:
            return "semantic"

        return "hybrid"

    def detect_source(self, query: str, explicit: str = "auto") -> str:
        """
        Return the target source index: 'alerts', 'elastalert', 'vulnerabilities',
        or 'all' (cross-index).

        Priority:
          1. Explicit API param (when not 'auto')
          2. Keyword auto-detection
          3. Default → 'alerts'
        """
        if explicit and explicit != "auto":
            return explicit

        q = query.lower()

        if any(k in q for k in self._VULN_KEYWORDS):
            return "vulnerabilities"

        if any(k in q for k in self._ELASTALERT_KEYWORDS):
            return "elastalert"

        # Optionally: cross-index when query is broad (agent name + no specific signal)
        if "all indices" in q or "everything" in q or "across all" in q:
            return "all"

        return "alerts"