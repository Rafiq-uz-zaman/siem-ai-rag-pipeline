from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any, Literal
from datetime import datetime
import re


# -----------------------------
# 🔍 Query Request Schema
# -----------------------------
class QueryRequest(BaseModel):
    query: str = Field(..., min_length=3, max_length=500)
    session_id: str = Field(..., min_length=3, max_length=100)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    size: Optional[int] = Field(default=10, ge=1, le=100)
    # Explicit index source — overrides keyword auto-detection when set
    source: Optional[Literal["auto", "alerts", "elastalert", "vulnerabilities"]] = "auto"

    @validator("start_time", "end_time", pre=True)
    def validate_time(cls, value):
        if value is None:
            return value
        try:
            return datetime.fromisoformat(value)
        except Exception:
            raise ValueError("Time must be ISO format")

    @validator("query")
    def sanitize_query(cls, value):
        # prevent ES query injection patterns
        forbidden = ["{", "}", "script", "painless"]
        if any(f in value.lower() for f in forbidden):
            raise ValueError("Invalid query content detected")
        return value


# -----------------------------
# 📊 Alert Schema
# -----------------------------
class Alert(BaseModel):
    timestamp: datetime = Field(..., alias="@timestamp")
    rule_id: Optional[str]
    agent_id: Optional[str]
    src_ip: Optional[str]
    dest_ip: Optional[str]
    severity: Optional[int]
    message: Optional[str]

    class Config:
        allow_population_by_field_name = True


# -----------------------------
# 🔗 Correlation Schema
# -----------------------------
class CorrelationResult(BaseModel):
    key: str
    alerts: List[Alert]
    count: int


# -----------------------------
# 📈 Aggregation Result
# -----------------------------
class AggregationBucket(BaseModel):
    key: str
    doc_count: int


class AggregationResponse(BaseModel):
    buckets: List[AggregationBucket]


# -----------------------------
# 📦 Retrieval Response
# -----------------------------
class RetrievalResponse(BaseModel):
    alerts: List[Alert]
    correlation: Dict[str, List[Alert]]


# -----------------------------
# 🚨 Final API Response
# -----------------------------
class QueryResponse(BaseModel):
    type: str
    result: Any
    execution_time_ms: int
