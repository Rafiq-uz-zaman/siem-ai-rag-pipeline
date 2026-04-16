from app.config import settings


class AggregationService:

    # ------------------------------------------------------------------
    # Wazuh Alerts
    # ------------------------------------------------------------------

    def top_ips(self, es_service, time_filter):
        body = {
            "size": 0,
            "query": {
                "range": {"@timestamp": time_filter}
            },
            "aggs": {
                "total_alerts": {
                    "value_count": {"field": "rule.id.keyword"}
                },
                "top_src_ips": {
                    "terms": {"field": "data.srcip.keyword", "size": 10}
                },
                "top_rules": {
                    "terms": {"field": "rule.id.keyword", "size": 10},
                    "aggs": {
                        "description": {
                            "terms": {"field": "rule.description.keyword", "size": 1}
                        }
                    }
                },
                "top_agents": {
                    "terms": {"field": "agent.name.keyword", "size": 10}
                },
                "severity_breakdown": {
                    "terms": {"field": "rule.level", "size": 15}
                }
            }
        }
        res = es_service.search(settings.ES_INDEX, body)
        aggs = res.get("aggregations", {})

        if not aggs:
            return {"error": "Aggregation failed — fields may not be indexed as keyword/numeric types."}

        top_rules = []
        for b in aggs.get("top_rules", {}).get("buckets", []):
            desc_buckets = b.get("description", {}).get("buckets", [])
            description = desc_buckets[0]["key"] if desc_buckets else "Unknown"
            top_rules.append({
                "rule_id": b["key"],
                "description": description,
                "count": b["doc_count"]
            })

        return {
            "source": "alerts",
            "total_alerts": aggs.get("total_alerts", {}).get("value", 0),
            "top_src_ips": [
                {"ip": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_src_ips", {}).get("buckets", [])
            ],
            "top_rules": top_rules,
            "top_agents": [
                {"agent": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_agents", {}).get("buckets", [])
            ],
            "severity_breakdown": [
                {"level": b["key"], "count": b["doc_count"]}
                for b in aggs.get("severity_breakdown", {}).get("buckets", [])
            ]
        }

    # ------------------------------------------------------------------
    # ElastAlert
    # ------------------------------------------------------------------

    def top_elastalert(self, es_service, time_filter):
        """Top fired rules, alert types, and severity breakdown from ElastAlert index."""
        # ElastAlert uses alert_time or @timestamp — try both
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "should": [
                        {"range": {"@timestamp": time_filter}},
                        {"range": {"alert_time": time_filter}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "total_alerts": {
                    "value_count": {"field": "rule_name.keyword"}
                },
                "top_rules": {
                    "terms": {"field": "rule_name.keyword", "size": 10}
                },
                "top_alert_types": {
                    "terms": {"field": "alert_type.keyword", "size": 10}
                },
                "severity_breakdown": {
                    "terms": {"field": "alert_severity.keyword", "size": 10}
                },
                "top_agents": {
                    "terms": {"field": "match_body.agent.name.keyword", "size": 10}
                }
            }
        }
        res = es_service.search(settings.ELASTALERT_INDEX, body)
        aggs = res.get("aggregations", {})

        if not aggs:
            return {"error": "ElastAlert aggregation failed."}

        return {
            "source": "elastalert",
            "total_alerts": aggs.get("total_alerts", {}).get("value", 0),
            "top_rules": [
                {"rule_name": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_rules", {}).get("buckets", [])
            ],
            "top_alert_types": [
                {"type": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_alert_types", {}).get("buckets", [])
            ],
            "severity_breakdown": [
                {"severity": b["key"], "count": b["doc_count"]}
                for b in aggs.get("severity_breakdown", {}).get("buckets", [])
            ],
            "top_agents": [
                {"agent": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_agents", {}).get("buckets", [])
            ]
        }

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------

    def top_vulnerabilities(self, es_service, time_filter):
        """Top CVEs, affected agents, severity breakdown, and top packages."""
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "should": [
                        {"range": {"vulnerability.detected_at": time_filter}},
                        {"range": {"vulnerability.published_at": time_filter}},
                        {"range": {"@timestamp": time_filter}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "total_vulns": {
                    "value_count": {"field": "vulnerability.id.keyword"}
                },
                "severity_breakdown": {
                    "terms": {"field": "vulnerability.severity.keyword", "size": 5}
                },
                "top_cves": {
                    "terms": {"field": "vulnerability.id.keyword", "size": 10},
                    "aggs": {
                        "severity": {
                            "terms": {"field": "vulnerability.severity.keyword", "size": 1}
                        },
                        "max_cvss": {
                            "max": {"field": "vulnerability.score.base"}
                        }
                    }
                },
                "top_affected_agents": {
                    "terms": {"field": "agent.name.keyword", "size": 10}
                },
                "top_packages": {
                    "terms": {"field": "package.name.keyword", "size": 10}
                },
                "top_os": {
                    "terms": {"field": "host.os.name.keyword", "size": 5}
                }
            }
        }
        res = es_service.search(settings.VULN_INDEX, body)
        aggs = res.get("aggregations", {})

        if not aggs:
            return {"error": "Vulnerability aggregation failed."}

        top_cves = []
        for b in aggs.get("top_cves", {}).get("buckets", []):
            sev_buckets = b.get("severity", {}).get("buckets", [])
            top_cves.append({
                "cve_id": b["key"],
                "count": b["doc_count"],
                "severity": sev_buckets[0]["key"] if sev_buckets else "unknown",
                "max_cvss": b.get("max_cvss", {}).get("value")
            })

        return {
            "source": "vulnerabilities",
            "total_vulnerabilities": aggs.get("total_vulns", {}).get("value", 0),
            "severity_breakdown": [
                {"severity": b["key"], "count": b["doc_count"]}
                for b in aggs.get("severity_breakdown", {}).get("buckets", [])
            ],
            "top_cves": top_cves,
            "top_affected_agents": [
                {"agent": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_affected_agents", {}).get("buckets", [])
            ],
            "top_packages": [
                {"package": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_packages", {}).get("buckets", [])
            ],
            "top_os": [
                {"os": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_os", {}).get("buckets", [])
            ]
        }

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    def run(self, es_service, time_filter, source: str = "alerts"):
        """Route aggregation to the correct method based on source."""
        if source == "elastalert":
            return self.top_elastalert(es_service, time_filter)
        if source == "vulnerabilities":
            return self.top_vulnerabilities(es_service, time_filter)
        if source == "all":
            return {
                "alerts": self.top_ips(es_service, time_filter),
                "elastalert": self.top_elastalert(es_service, time_filter),
                "vulnerabilities": self.top_vulnerabilities(es_service, time_filter),
            }
        return self.top_ips(es_service, time_filter)
        body = {
            "size": 0,
            "query": {
                "range": {"@timestamp": time_filter}
            },
            "aggs": {
                "total_alerts": {
                    "value_count": {"field": "rule.id.keyword"}
                },
                "top_src_ips": {
                    "terms": {"field": "data.srcip.keyword", "size": 10}
                },
                "top_rules": {
                    "terms": {"field": "rule.id.keyword", "size": 10},
                    "aggs": {
                        "description": {
                            "terms": {"field": "rule.description.keyword", "size": 1}
                        }
                    }
                },
                "top_agents": {
                    "terms": {"field": "agent.name.keyword", "size": 10}
                },
                "severity_breakdown": {
                    "terms": {"field": "rule.level", "size": 15}
                }
            }
        }
        res = es_service.search(settings.ES_INDEX, body)
        aggs = res.get("aggregations", {})

        if not aggs:
            return {"error": "Aggregation failed — fields may not be indexed as keyword/numeric types."}

        # Enrich top_rules with description from sub-aggregation
        top_rules = []
        for b in aggs.get("top_rules", {}).get("buckets", []):
            desc_buckets = b.get("description", {}).get("buckets", [])
            description = desc_buckets[0]["key"] if desc_buckets else "Unknown"
            top_rules.append({
                "rule_id": b["key"],
                "description": description,
                "count": b["doc_count"]
            })

        return {
            "total_alerts": aggs.get("total_alerts", {}).get("value", 0),
            "top_src_ips": [
                {"ip": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_src_ips", {}).get("buckets", [])
            ],
            "top_rules": top_rules,
            "top_agents": [
                {"agent": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_agents", {}).get("buckets", [])
            ],
            "severity_breakdown": [
                {"level": b["key"], "count": b["doc_count"]}
                for b in aggs.get("severity_breakdown", {}).get("buckets", [])
            ]
        }
