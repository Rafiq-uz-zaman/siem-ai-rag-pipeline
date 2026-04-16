import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root (parent of the app/ package)
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_env_path)

class Settings:
    ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")

    # Source indices
    ES_INDEX = "wazuh-alerts-4.x-remap-*"
    ELASTALERT_INDEX = "elastalert"
    VULN_INDEX = "wazuh-states-vulnerabilities-*"

    # Unified vector index (all sources share one index via source_type field)
    VECTOR_INDEX = "wazuh-alerts-vector"

    REDIS_HOST = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT = 6379

    EMBEDDING_MODEL = "all-MiniLM-L6-v2"

    BATCH_SIZE = 64
    POLL_INTERVAL = 5  # seconds

    TIME_FIELD = "@timestamp"

settings = Settings()