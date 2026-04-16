import json
import logging
from app.config import settings

logger = logging.getLogger(__name__)


def _is_redis_available() -> bool:
    try:
        import redis as _redis
        r = _redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            socket_connect_timeout=2,
        )
        r.ping()
        return True
    except Exception:
        return False


REDIS_AVAILABLE = _is_redis_available()

if REDIS_AVAILABLE:
    logger.info("Redis connected — session memory will persist across restarts.")
else:
    logger.warning(
        "Redis unavailable — using LangChain ConversationBufferMemory (in-process, lost on restart)."
    )


class MemoryService:
    """
    Session memory with two backends:

    - Redis available  : last result stored in Redis (TTL 1 h); chat turns also
                         tracked in a per-session ConversationBufferMemory so
                         follow-up queries can reference the conversation.
    - Redis unavailable: ConversationBufferMemory only (in-process dict).

    Public API
    ----------
    save_user_message(session_id, query)   -- log the user's turn
    save_query(session_id, result)         -- store result + log as AI turn
    get_last(session_id)                   -- return last stored result
    get_chat_history(session_id)           -- return LangChain message list
    clear_session(session_id)              -- wipe everything for a session
    """

    def __init__(self):
        self._buffer_memories: dict = {}   # session_id → ConversationBufferMemory
        self._local_store: dict = {}       # session_id → last result (fallback)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _default(obj):
        """JSON serialiser for ES ObjectApiResponse wrappers."""
        if hasattr(obj, "body"):
            return obj.body
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        raise TypeError(f"Not serializable: {type(obj).__name__}")

    def _get_redis(self):
        import redis
        return redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            decode_responses=True,
            socket_connect_timeout=2,
        )

    def _get_buffer_memory(self, session_id: str):
        """Return (or lazily create) a LangChain chat history store for this session.

        LangChain ≥1.0 removed ConversationBufferMemory; the canonical replacement
        is InMemoryChatMessageHistory from langchain_core.
        """
        if session_id not in self._buffer_memories:
            from langchain_core.chat_history import InMemoryChatMessageHistory
            self._buffer_memories[session_id] = InMemoryChatMessageHistory()
        return self._buffer_memories[session_id]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save_user_message(self, session_id: str, query: str) -> None:
        """Log the user query as a Human turn in chat history."""
        try:
            self._get_buffer_memory(session_id).add_user_message(query)
        except Exception as e:
            logger.warning(f"Failed to log user message to buffer memory: {e}")

    def save_query(self, session_id: str, result) -> None:
        """Persist query result for follow-up retrieval and log as an AI turn."""
        serialized = json.dumps(result, default=self._default)

        # 1. Persist to Redis when available (survives restarts)
        if REDIS_AVAILABLE:
            try:
                self._get_redis().set(f"session:{session_id}", serialized, ex=3600)
            except Exception as e:
                logger.warning(f"Redis save failed ({e}); storing in-process.")
                self._local_store[session_id] = result
        else:
            self._local_store[session_id] = result

        # 2. Log a truncated summary as an AI turn in InMemoryChatMessageHistory
        try:
            summary = serialized[:500]
            self._get_buffer_memory(session_id).add_ai_message(summary)
        except Exception as e:
            logger.warning(f"Chat history update failed: {e}")

    def get_last(self, session_id: str):
        """Return the last stored result for this session (or None)."""
        if REDIS_AVAILABLE:
            try:
                raw = self._get_redis().get(f"session:{session_id}")
                if raw:
                    return json.loads(raw)
            except Exception as e:
                logger.warning(f"Redis get failed ({e}); checking local store.")
        return self._local_store.get(session_id)

    def get_chat_history(self, session_id: str) -> list:
        """Return the LangChain message list for this session."""
        try:
            return self._get_buffer_memory(session_id).messages
        except Exception:
            return []

    def clear_session(self, session_id: str) -> None:
        """Wipe Redis key and in-process state for this session."""
        if REDIS_AVAILABLE:
            try:
                self._get_redis().delete(f"session:{session_id}")
            except Exception:
                pass
        self._local_store.pop(session_id, None)
        self._buffer_memories.pop(session_id, None)
