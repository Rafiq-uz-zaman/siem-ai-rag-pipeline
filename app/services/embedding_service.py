from sentence_transformers import SentenceTransformer
import time
from app.metrics import EMBEDDING_TIME
from app.config import settings

class EmbeddingService:
    def __init__(self):
        self.model = SentenceTransformer(settings.EMBEDDING_MODEL)

    def encode_batch(self, texts):
        start = time.time()
        result = self.model.encode(texts, batch_size=settings.BATCH_SIZE, normalize_embeddings=True)
        EMBEDDING_TIME.observe(time.time() - start)
        return result

    def encode_query(self, text):
        return self.model.encode([text], normalize_embeddings=True)[0]