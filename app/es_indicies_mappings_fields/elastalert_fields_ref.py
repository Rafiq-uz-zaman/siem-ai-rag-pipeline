ELASTALERT_FIELD_REFERENCE = {
    "core_fields": {
        "alert_time": ["alert_time", "@timestamp"],
        "rule_name": "rule_name",
        "alert_type": "alert_type",
        "alert_description": "alert_description",
        "alert_severity": "alert_severity",
        "alert_info": "alert_info"
    },

    "match_body": {
        "agent_id": "match_body.agent.id",
        "agent_name": "match_body.agent.name",
        "agent_ip": "match_body.agent.ip",

        "rule_id": "match_body.rule.id",
        "rule_level": "match_body.rule.level",
        "rule_description": "match_body.rule.description",
        "rule_groups": "match_body.rule.groups",

        "full_log": "match_body.full_log"  # reference only
    },

    "aggregation_safe_fields": {
        "agent_name": "match_body.agent.name",
        "alert_type": "alert_type",
        "rule_name": "rule_name",
        "alert_severity": "alert_severity"
    }
}

ELASTALERT_SEVERITY_MAPPING = {
    "high": ["high", "critical", 3],
    "medium": ["medium", 2],
    "low": ["low", 1]
}

CUSTOM_RULE_HINTS = [
    "rule_name",
    "alert_description",
    "alert_info"
]
