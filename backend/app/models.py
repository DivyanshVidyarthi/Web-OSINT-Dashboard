from pydantic import BaseModel, Field


class InvestigateRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)


class InvestigationSummary(BaseModel):
    id: str
    target: str
    target_type: str
    status: str
    created_at: str


class HealthResponse(BaseModel):
    status: str
    version: str
    configured_sources: dict[str, bool]
