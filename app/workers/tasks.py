from app.workers.celery_worker import celery_app

@celery_app.task(bind=True, max_retries=3)
def process_alert_batch(self, alerts):
    try:
        from app.services.embedding_service import EmbeddingService
        from app.services.elasticsearch_service import ElasticsearchService
        from app.config import settings

        embedder = EmbeddingService()
        es = ElasticsearchService()

        alerts = [a for a in alerts if a.get("message")]
        texts = [a["message"] for a in alerts]
        embeddings = embedder.encode_batch(texts)

        actions = []
        for a, e in zip(alerts, embeddings):
            a["embedding"] = e.tolist()
            actions.append({
                "_index": settings.VECTOR_INDEX,
                "_source": a
            })

        es.bulk_index(actions)

    except Exception as e:
        raise self.retry(exc=e, countdown=5)