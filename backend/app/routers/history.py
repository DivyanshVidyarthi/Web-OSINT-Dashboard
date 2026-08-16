from fastapi import APIRouter, HTTPException

from .. import db

router = APIRouter(prefix="/api", tags=["history"])


@router.get("/investigations")
def list_investigations():
    return db.list_investigations()


@router.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: str):
    record = db.get_investigation(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return record


@router.delete("/investigations/{investigation_id}")
def delete_investigation(investigation_id: str):
    deleted = db.delete_investigation(investigation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"deleted": True, "id": investigation_id}


@router.delete("/investigations")
def clear_all_investigations():
    db.clear_history()
    return {"cleared": True}
