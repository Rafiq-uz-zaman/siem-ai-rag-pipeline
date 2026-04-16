# SIEM RAG System (No LLM)

## 🚀 Overview

This project implements a **production-grade Retrieval-Augmented Generation (RAG) system WITHOUT any LLM** for Security Operations Centers (SOC).

It is designed to work with **Wazuh alerts stored in Elasticsearch** and provides:

* 🔍 Hybrid Retrieval (BM25 + Vector Search)
* ⚡ Real-time alert ingestion & processing
* 🧠 Rule-based query understanding (NO AI reasoning)
* 🔗 Alert correlation (IP-based grouping)
* 🚨 Basic anomaly detection (spike detection)
* 💾 Session-aware memory (Redis)

> ⚠️ This system is built for **accuracy, determinism, and zero hallucination**.

---

## 🧱 Architecture

```
                   ┌──────────────────────┐
                   │      FastAPI API     │
                   └──────────┬───────────┘
                              │
                              ▼
                   ┌──────────────────────┐
                   │  Query Classifier    │
                   └──────────┬───────────┘
                              │
                              ▼
                   ┌──────────────────────┐
                   │     Retriever        │
                   │ (Hybrid Search)      │
                   └──────────┬───────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                                           ▼
┌──────────────────────┐                 ┌──────────────────────┐
│ Elasticsearch (Logs) │                 │ Elasticsearch (Vector)│
└──────────────────────┘                 └──────────────────────┘
                              ▲
                              │
                   ┌──────────────────────┐
                   │ Embedding Service    │
                   └──────────┬───────────┘
                              │
                   ┌──────────────────────┐
                   │ Celery Workers       │
                   └──────────┬───────────┘
                              │
                   ┌──────────────────────┐
                   │ Streaming Worker     │
                   └──────────────────────┘

                   ┌──────────────────────┐
                   │ Redis (Memory + Queue)│
                   └──────────────────────┘
```

---

## 📦 Core Features

### 🔍 1. Hybrid Retrieval Engine

* Combines:

  * **BM25 keyword search**
  * **Dense vector similarity (cosine)**
* Uses Elasticsearch `dense_vector` with KNN
* Time-filtered queries for accuracy

---

### ⚡ 2. Real-Time Streaming Pipeline

* Polls new alerts from `wazuh-alerts-*`
* Processes only **new data using timestamps**
* Generates embeddings asynchronously via Celery
* Indexes enriched alerts into vector index

---

### 🧠 3. Query Classification (Rule-Based)

Deterministic classification (no ML/LLM):

| Type        | Example                         |
| ----------- | ------------------------------- |
| Aggregation | "top source IPs"                |
| Semantic    | "alerts similar to brute force" |
| Hybrid      | "failed login from 192.168.1.1" |
| Follow-up   | "how many from above?"          |

---

### 💾 4. Memory System (Redis)

* Stores session-based query results
* Enables contextual queries:

  * “from above”
  * “previous results”
* TTL-based expiration

---

### 🔗 5. Alert Correlation

* Groups alerts by `src_ip`
* Identifies repeated attack patterns
* Returns structured correlation map

---

### 🚨 6. Anomaly Detection

* Detects spikes in alert volume
* Compares:

  * Current count vs historical average
* Flags abnormal activity

---

### 📊 7. Observability

* JSON structured logging
* Prometheus metrics:

  * Request count
  * Query latency
  * Embedding latency

---

## 📁 Project Structure

```
siem_rag/
│
├── app/
│   ├── main.py
│   ├── config.py
│   ├── logging_config.py
│   ├── metrics.py
│
│   ├── services/
│   │   ├── elasticsearch_service.py
│   │   ├── embedding_service.py
│   │   ├── memory_service.py
│
│   ├── core/
│   │   ├── retriever.py
│   │   ├── query_classifier.py
│   │   ├── aggregation.py
│   │   ├── correlation.py
│   │   ├── anomaly_detection.py
│
│   ├── workers/
│   │   ├── streaming_worker.py
│   │   ├── celery_worker.py
│   │   ├── tasks.py
│
│   └── models/
│       ├── schemas.py
│
├── Dockerfile.api
├── Dockerfile.worker
├── docker-compose.yml
├── k8s/
│   ├── api-deployment.yaml
│   ├── worker-deployment.yaml
│   ├── service.yaml
│   ├── hpa.yaml
│
├── requirements.txt
└── README.md
```

---

## 🔧 Elasticsearch Setup

### Source Index

```
wazuh-alerts-*
```

### Vector Index Mapping

```json
{
  "mappings": {
    "properties": {
      "@timestamp": {"type": "date"},
      "rule_id": {"type": "keyword"},
      "agent_id": {"type": "keyword"},
      "src_ip": {"type": "ip"},
      "dest_ip": {"type": "ip"},
      "severity": {"type": "integer"},
      "message": {"type": "text"},
      "embedding": {
        "type": "dense_vector",
        "dims": 384,
        "index": true,
        "similarity": "cosine"
      }
    }
  }
}
```

---

## 🐳 Running Locally (Docker)

### 1. Start Services

```bash
docker-compose up --build
```

### 2. API Access

```
http://localhost:8000
```

### 3. Metrics Endpoint

```
http://localhost:8000/metrics
```

---

## ☸️ Kubernetes Deployment

Apply all resources:

```bash
kubectl apply -f k8s/
```

### Includes:

* API Deployment (scalable)
* Worker Deployment
* LoadBalancer Service
* Horizontal Pod Autoscaler (HPA)

---

## 📡 API Usage

### Endpoint

```
POST /query
```

### Request

```json
{
  "query": "top source IPs",
  "session_id": "session-123"
}
```

### Response

```json
{
  "type": "aggregation",
  "result": {...},
  "execution_time_ms": 45
}
```

---

## ⚙️ Scaling Strategy

| Component      | Strategy                       |
| -------------- | ------------------------------ |
| FastAPI        | Horizontal scaling (stateless) |
| Celery Workers | Queue-based scaling            |
| Elasticsearch  | Sharding + ILM                 |
| Redis          | Cluster mode                   |

---

## 📈 Observability

### Logging

* JSON structured logs
* Compatible with ELK / OpenSearch

### Metrics (Prometheus)

* `api_requests_total`
* `query_latency_seconds`
* `embedding_time_seconds`

---

## 🔐 Security

* Query sanitization (prevents injection)
* No dynamic scripting
* Strict schema validation
* No LLM → no hallucination risk

---

## ⚠️ Limitations

* No natural language reasoning (intentional)
* Rule-based query classification only
* Basic anomaly detection (non-ML)

---

## 🚀 Production Recommendations

* Use Kafka for high-throughput ingestion (>50K EPS)
* Deploy Elasticsearch with:

  * Hot/Warm architecture
  * ILM policies
* Enable TLS + authentication
* Use Redis Cluster
* Add RBAC for multi-tenant SOC

---

## 🔮 Future Enhancements

* Threat intelligence enrichment (MISP, AbuseIPDB)
* GeoIP tagging
* Sigma rule execution engine
* ML-based anomaly detection
* SOC dashboard UI

---

## 📜 License

Internal SOC / Enterprise Use Only
