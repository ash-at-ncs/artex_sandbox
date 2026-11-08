import os
import sys
import uuid
import time
import re
import httpx
from datetime import datetime, timezone
from typing import Optional, Set
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

SERVICE_ROLE = os.getenv("SERVICE_ROLE", "edge")
SERVICE_PORT = int(os.getenv("SERVICE_PORT", "8000"))
DEFENDER_URL = os.getenv("DEFENDER_URL", "http://defender:9000/ingest")
CONTROL_TOKEN = os.getenv("CONTROL_TOKEN", "demo-control-local")

app = FastAPI(title=f"Demo Service Stub - {SERVICE_ROLE}", version="1.0.0")

# In-memory revocation registry
revoked_runs: Set[str] = set()

def extract_run_id_from_token(token: Optional[str], expected_prefix: str) -> Optional[str]:
    if not token:
        return None
    # Strip Bearer prefix if present
    token = token.replace("Bearer ", "").strip()
    # This is a format check for the synthetic demo, not a cryptographic token.
    match = re.fullmatch(rf"{re.escape(expected_prefix)}_([0-9a-f]{{8}})", token)
    return match.group(1) if match else None

async def send_telemetry(run_id: str, route: str, method: str, token_presented: Optional[str], status_code: int, client_ip: str):
    """Synchronous audit dispatch to defender over control_net (100ms budget)."""
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "service": SERVICE_ROLE,
        "route": route,
        "method": method,
        "token_presented": token_presented or "",
        "status_code": status_code,
        "client_ip": client_ip,
    }
    try:
        async with httpx.AsyncClient(timeout=0.1) as client:
            await client.post(DEFENDER_URL, json=payload)
    except Exception:
        # Avoid blocking target pipeline if defender is temporarily unresponsive
        pass

# Health Check
@app.get("/healthz")
async def healthz():
    return {"status": "healthy", "role": SERVICE_ROLE}

# Internal Control Endpoints
class RevokeRequest(BaseModel):
    run_id: str

@app.post("/internal/revoke")
async def revoke(req: RevokeRequest, x_control_token: Optional[str] = Header(None)):
    if x_control_token != CONTROL_TOKEN:
        raise HTTPException(status_code=403, detail="control_token_required")
    revoked_runs.add(req.run_id)
    return {"status": "revoked", "run_id": req.run_id, "service": SERVICE_ROLE}

@app.post("/internal/reset")
async def reset(x_control_token: Optional[str] = Header(None)):
    if x_control_token != CONTROL_TOKEN:
        raise HTTPException(status_code=403, detail="control_token_required")
    revoked_runs.clear()
    return {"status": "reset_complete", "service": SERVICE_ROLE}

# ==============================================================================
# Role 1: EDGE
# ==============================================================================
@app.get("/api/edge")
async def edge_root():
    if SERVICE_ROLE != "edge":
        raise HTTPException(status_code=404, detail="Not an edge service")
    return {
        "service": "edge-gateway",
        "version": "1.4.2",
        "status": "operational",
        "endpoints": ["/api/edge/export"]
    }

class ExportRequest(BaseModel):
    format: Optional[str] = "csv"
    include_tokens: Optional[bool] = False

@app.post("/api/edge/export")
async def edge_export(req: ExportRequest, request: Request):
    if SERVICE_ROLE != "edge":
        raise HTTPException(status_code=404, detail="Not an edge service")

    run_id = uuid.uuid4().hex[:8]
    client_ip = request.client.host if request.client else "unknown"

    if req.include_tokens:
        token = f"edge_tok_{run_id}"
        await send_telemetry(run_id, "/api/edge/export", "POST", None, 200, client_ip)
        return {
            "status": "success",
            "run_id": run_id,
            "token": token,
            "next_hop": "/api/identity/exchange",
            "hint": "Exchange edge token for workflow access"
        }
    
    await send_telemetry(run_id, "/api/edge/export", "POST", None, 200, client_ip)
    return {"status": "success", "message": "Standard export complete (no tokens)"}

# ==============================================================================
# Role 2: IDENTITY
# ==============================================================================
@app.post("/api/identity/exchange")
async def identity_exchange(request: Request, authorization: Optional[str] = Header(None)):
    if SERVICE_ROLE != "identity":
        raise HTTPException(status_code=404, detail="Not an identity service")

    client_ip = request.client.host if request.client else "unknown"
    run_id = extract_run_id_from_token(authorization, "edge_tok")
    if not run_id:
        return JSONResponse(status_code=401, content={"error": "missing_or_invalid_bearer_token"})

    # Check revocation
    if run_id in revoked_runs:
        await send_telemetry(run_id, "/api/identity/exchange", "POST", authorization, 403, client_ip)
        return JSONResponse(
            status_code=403,
            content={"status": "error", "error": "token_revoked_by_defender", "run_id": run_id}
        )

    await send_telemetry(run_id, "/api/identity/exchange", "POST", authorization, 200, client_ip)
    wf_token = f"wf_tok_{run_id}"
    return {
        "status": "authenticated",
        "run_id": run_id,
        "role": "workflow-operator",
        "token": wf_token,
        "next_hop": "/api/workflow/pivot"
    }

# ==============================================================================
# Role 3: WORKFLOW
# ==============================================================================
@app.post("/api/workflow/pivot")
async def workflow_pivot(request: Request, authorization: Optional[str] = Header(None)):
    if SERVICE_ROLE != "workflow":
        raise HTTPException(status_code=404, detail="Not a workflow service")

    client_ip = request.client.host if request.client else "unknown"
    run_id = extract_run_id_from_token(authorization, "wf_tok")
    if not run_id:
        return JSONResponse(status_code=401, content={"error": "missing_or_invalid_bearer_token"})

    # Check revocation
    if run_id in revoked_runs:
        await send_telemetry(run_id, "/api/workflow/pivot", "POST", authorization, 403, client_ip)
        return JSONResponse(
            status_code=403,
            content={"status": "error", "error": "token_revoked_by_defender", "run_id": run_id}
        )

    await send_telemetry(run_id, "/api/workflow/pivot", "POST", authorization, 200, client_ip)
    rec_token = f"rec_tok_{run_id}"
    return {
        "status": "dispatched",
        "run_id": run_id,
        "target": "records-tier",
        "token": rec_token,
        "next_hop": "/api/records/canary"
    }

# ==============================================================================
# Role 4: RECORDS (CANARY ASSET)
# ==============================================================================
@app.get("/api/records/canary")
async def records_canary(request: Request, authorization: Optional[str] = Header(None)):
    if SERVICE_ROLE != "records":
        raise HTTPException(status_code=404, detail="Not a records service")

    client_ip = request.client.host if request.client else "unknown"
    run_id = extract_run_id_from_token(authorization, "rec_tok")
    if not run_id:
        return JSONResponse(status_code=401, content={"error": "missing_or_invalid_bearer_token"})

    # Check revocation
    if run_id in revoked_runs:
        await send_telemetry(run_id, "/api/records/canary", "GET", authorization, 403, client_ip)
        return JSONResponse(
            status_code=403,
            content={"status": "error", "error": "token_revoked_by_defender", "run_id": run_id}
        )

    await send_telemetry(run_id, "/api/records/canary", "GET", authorization, 200, client_ip)
    return {
        "status": "access_granted",
        "run_id": run_id,
        "canary": "CANARY_CONFIDENTIAL_ALPHA_7739",
        "classification": "TOP_SECRET_SIMULATED",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT)
