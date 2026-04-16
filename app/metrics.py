from prometheus_client import Counter, Histogram

REQUEST_COUNT = Counter("api_requests_total", "Total API Requests")
QUERY_LATENCY = Histogram("query_latency_seconds", "Query latency")
EMBEDDING_TIME = Histogram("embedding_time_seconds", "Embedding time")