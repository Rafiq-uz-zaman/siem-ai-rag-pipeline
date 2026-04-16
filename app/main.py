from fastapi import FastAPI, Response
import time

from app.services.elasticsearch_service import ElasticsearchService
from app.services.embedding_service import EmbeddingService
from app.services.memory_service import MemoryService

from app.core.retriever import Retriever
from app.core.query_classifier import QueryClassifier
from app.core.aggregation import AggregationService

from app.metrics import REQUEST_COUNT, QUERY_LATENCY
from app.logging_config import setup_logging
from app.models.schemas import QueryRequest
from prometheus_client import generate_latest

app = FastAPI()
setup_logging()

es = ElasticsearchService()
embedder = EmbeddingService()
memory = MemoryService()

retriever = Retriever(es, embedder)
classifier = QueryClassifier()
agg = AggregationService()


@app.on_event("startup")
def startup():
    es.ensure_vector_index()


@app.post("/query")
def query(req: QueryRequest):

    REQUEST_COUNT.inc()
    start = time.time()

    q_type = classifier.classify(req.query)

    time_filter = {
        "gte": req.start_time.isoformat() if req.start_time else "now-24h",
        "lte": req.end_time.isoformat() if req.end_time else "now"
    }

    # Record the user turn before processing
    memory.save_user_message(req.session_id, req.query)

    # Detect target source index (explicit param > keyword auto-detect)
    source = classifier.detect_source(req.query, explicit=req.source)

    if q_type == "aggregation":
        result = agg.run(es, time_filter, source=source)

    elif q_type == "follow_up":
        result = memory.get_last(req.session_id) or {"message": "No previous query found for this session."}

    else:
        result = retriever.retrieve(req.query, time_filter, size=req.size, source=source)

    memory.save_query(req.session_id, result)

    QUERY_LATENCY.observe(time.time() - start)

    return {"type": q_type, "source": source, "result": result}


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type="text/plain")
