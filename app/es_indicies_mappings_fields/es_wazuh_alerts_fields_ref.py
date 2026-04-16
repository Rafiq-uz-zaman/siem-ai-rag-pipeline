# Wazuh Field Reference for Query Generation
# Based on wazuh-template.json index template

WAZUH_FIELD_REFERENCE = {
    "core_fields": {
        "timestamp": "@timestamp",
        "rule_id": "rule.id",
        "rule_level": "rule.level", 
        "rule_description": "rule.description",
        "rule_groups": "rule.groups",
        "agent_id": "agent.id",
        "agent_name": "agent.name",
        "agent_ip": "agent.ip",
        "location": "location",
        "full_log": "full_log",
        "message": "message"
    },
    
    "security_fields": {
        "source_ip": ["data.srcip", "data.src_ip", "data.aws.sourceIPAddress"],
        "destination_ip": ["data.dstip", "data.aws.dstaddr"],
        "source_port": ["data.srcport", "data.src_port"],
        "destination_port": ["data.dstport"],
        "source_user": ["data.srcuser", "data.win.eventdata.subjectUserName"],
        "destination_user": ["data.dstuser", "data.win.eventdata.targetUserName"],
        "protocol": ["data.protocol"],
        "action": ["data.action", "data.aws.action"],
        "status": ["data.status"]
    },
    
    "authentication_fields": {
        "windows_logon": {
            "user": "data.win.eventdata.targetUserName",
            "domain": "data.win.eventdata.targetDomainName", 
            "logon_type": "data.win.eventdata.logonType",
            "workstation": "data.win.eventdata.workstationName",
            "process": "data.win.eventdata.processName",
            "logon_id": "data.win.eventdata.targetLogonId"
        },
        "linux_auth": {
            "user": "data.audit.uid",
            "effective_user": "data.audit.euid",
            "command": "data.audit.command",
            "executable": "data.audit.exe",
            "tty": "data.audit.tty"
        }
    },
    
    "network_fields": {
        "firewall": {
            "action": "data.action",
            "source_ip": "data.srcip",
            "dest_ip": "data.dstip", 
            "source_port": "data.srcport",
            "dest_port": "data.dstport",
            "protocol": "data.protocol"
        },
        "aws": {
            "vpc_flow": {
                "account_id": "data.aws.accountId",
                "src_addr": "data.aws.srcaddr",
                "dst_addr": "data.aws.dstaddr",
                "start_time": "data.aws.start",
                "end_time": "data.aws.end",
                "action": "data.aws.action",
                "bytes": "data.aws.bytes"
            }
        }
    },
    
    "file_integrity": {
        "syscheck": {
            "path": "syscheck.path",
            "event": "syscheck.event", 
            "sha256_before": "syscheck.sha256_before",
            "sha1_after": "syscheck.sha1_before",
            "md5_before": "syscheck.md5_before",
            "md5_after": "syscheck.md5_after",
            "permissions": "syscheck.perm_after",
            "owner": "syscheck.uname_after"
        }
    },
    
    "mitre_attack": {
        "technique": "rule.mitre.technique",      
        "tactic": "rule.mitre.tactic",            
        "technique_id": "rule.mitre.id"           
    },
    
    "compliance": {
        "pci_dss": "rule.pci_dss",
        "gdpr": "rule.gdpr",
        "hipaa": "rule.hipaa",
        "nist": "rule.nist_800_53",
        "cis": "rule.cis"
    },
    
    "common_queries": {
        "brute_force": {
            "rule_groups": ["authentication_failed", "authentication_failures"],
            "rule_ids": ["591", "550", "81802", "510", "111801"],
            "fields": ["data.srcip", "data.win.eventdata.targetUserName", "data.win.eventdata.workstationName"]
        },
        "malware": {
            "rule_groups": ["malware", "rootcheck", "virustotal"],
            "fields": ["data.virustotal.malicious", "data.virustotal.positives", "syscheck.path"]
        },
        "lateral_movement": {
            "rule_groups": ["windows", "sysmon"],
            "mitre_tactics": ["lateral-movement"],
            "fields": ["data.win.eventdata.parentImage", "data.win.eventdata.image"]
        },
        "privilege_escalation": {
            "rule_groups": ["privilege-escalation", "sudo"],
            "fields": ["data.audit.uid", "data.audit.euid", "data.audit.command"]
        }
    }
}

# Common Elasticsearch aggregation patterns for Wazuh data
COMMON_AGGREGATIONS = {
    "top_source_ips": {
        "terms": {"field": "data.srcip.keyword", "size": 10}
    },
    "rule_frequency": {
        "terms": {"field": "rule.id.keyword", "size": 20}
    },
    "agent_activity": {
        "terms": {"field": "agent.name.keyword", "size": 10}
    },
    "timeline": {
        "date_histogram": {
            "field": "@timestamp",
            "calendar_interval": "1h"
        }
    }
}

KEYWORD_FIELDS = {
    "agent.name": "agent.name.keyword",
    "rule.id": "rule.id.keyword",
    "rule.groups": "rule.groups",
    "location": "location.keyword",
    "data.srcip": "data.srcip",
    "data.dstip": "data.dstip"
}

