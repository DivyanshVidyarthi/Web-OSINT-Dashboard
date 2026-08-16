import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException

from ..models import InvestigateRequest
from ..osint.utils import detect_target_type, ValidationError
from ..aggregator import investigate as run_investigation
from ..rate_limit import rate_limit_dependency
from .. import db

logger = logging.getLogger("osint.router.investigate")

router = APIRouter(prefix="/api", tags=["investigate"])


@router.post("/investigate", dependencies=[Depends(rate_limit_dependency)])
def investigate_target(payload: InvestigateRequest):
    try:
        target_type, normalized_target = detect_target_type(payload.target)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    investigation_id = str(uuid.uuid4())

    try:
        result = run_investigation(normalized_target, target_type)
    except Exception as exc:  # noqa: BLE001
        # Should not normally happen — the aggregator itself catches
        # per-module failures — but never let an unexpected error 500
        # without an explanation, and never crash the process.
        logger.exception("Investigation failed unexpectedly")
        raise HTTPException(status_code=500, detail="Investigation failed unexpectedly") from exc

    result["id"] = investigation_id
    db.save_investigation(
        investigation_id, normalized_target, target_type.value, result["status"], result
    )
    return result
