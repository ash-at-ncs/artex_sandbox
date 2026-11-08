import os
import time
import asyncio
import httpx
import numpy as np
from datetime import datetime, timezone
from typing import Dict, List, Optional
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest

DEFENDER_PORT = int(os.getenv("DEFENDER_PORT", "9000"))
IDENTITY_URL = os.getenv("IDENTITY_URL", "http://identity:8000/internal/revoke")
WORKFLOW_URL = os.getenv("WORKFLOW_URL", "http://workflow:8000/internal/revoke")
RECORDS_URL = os.getenv("RECORDS_URL", "http://records:8000/internal/revoke")
CONTROL_TOKEN = os.getenv("CONTROL_TOKEN", "demo-control-local")

app = FastAPI(title="ML Defender IsolationForest Service", version="1.0.0")

# Route sensitivity weights
ROUTE_WEIGHTS = {
    "/api/edge": 0.1,
    "/api/edge/export": 0.5,
    "/api/identity/exchange": 0.8,
    "/api/workflow/pivot": 0.9,
    "/api/records/canary": 1.0,
}
SERVICE_ORDER = ["edge", "identity", "workflow", "records"]

# Per-run tracking state
class RunTracker:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.hop_count = 0
        self.services_visited: Set[str] = set()
        self.events: List[dict] = []
        self.contained = False
        self.containment_time: Optional[float] = None
        self.anomaly_score: float = 0.0
        self.last_service_index = -1

trackers: Dict[str, RunTracker] = {}
audit_trail: List[dict] = []
defender_mode: str = "observe" # "observe" | "active"

def init_model() -> IsolationForest:
    """Pre-trains IsolationForest with calibrated baseline and anomaly features."""
    rng = np.random.RandomState(42)
    # Features: [hop_count, distinct_services, pivot_velocity, route_sensitivity, out_of_order]
    # Normal: low hop count, slow velocity (0.01 - 0.1), low sensitivity (0.1 - 0.5), in order
    X_normal = []
    for _ in range(1000):
        hops = rng.randint(1, 3)
        services = rng.randint(1, 3)
        velocity = rng.uniform(0.01, 0.2)
        sensitivity = rng.uniform(0.1, 0.5)
        out_of_order = 0.0
        X_normal.append([hops, services, velocity, sensitivity, out_of_order])

    # Attack: rapid traversal, high velocity (0.5 - 2.0), multiple services, high sensitivity
    X_attack = []
    for _ in range(50):
        hops = rng.randint(2, 5)
        services = rng.randint(2, 4)
        velocity = rng.uniform(0.5, 3.0)
        sensitivity = rng.uniform(0.7, 1.0)
        out_of_order = 0.0
        X_attack.append([hops, services, velocity, sensitivity, out_of_order])

    X_train = np.vstack([X_normal, X_attack])
    clf = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    clf.fit(X_train)
    return clf

model = init_model()

@app.get("/healthz")
async def healthz():
    return {"status": "healthy", "service": "defender"}

@app.post("/internal/reset")
async def reset(x_control_token: Optional[str] = Header(None)):
    if x_control_token != CONTROL_TOKEN:
        raise HTTPException(status_code=403, detail="control_token_required")
    global trackers, audit_trail
    trackers.clear()
    audit_trail.clear()
    return {"status": "reset_complete"}

@app.post("/internal/mode")
async def set_mode(payload: dict, x_control_token: Optional[str] = Header(None)):
    if x_control_token != CONTROL_TOKEN:
        raise HTTPException(status_code=403, detail="control_token_required")
    global defender_mode
    mode = payload.get("mode", "observe")
    if mode not in ["observe", "active"]:
        raise HTTPException(status_code=400, detail="invalid_mode")
    defender_mode = mode
    return {"status": "mode_updated", "mode": defender_mode}

class TelemetryEvent(BaseModel):
    timestamp: str
    run_id: str
    service: str
    route: str
    method: str
    token_presented: Optional[str] = ""
    status_code: int
    client_ip: str

@app.post("/ingest")
async def ingest(event: TelemetryEvent):
    now = time.time()
    run_id = event.run_id

    if run_id not in trackers:
        trackers[run_id] = RunTracker(run_id)

    tr = trackers[run_id]
    delta_t = max(0.001, now - tr.last_seen) if tr.hop_count > 0 else 1.0
    tr.last_seen = now
    tr.hop_count += 1
    tr.services_visited.add(event.service)
    tr.events.append(event.model_dump())

    # Calculate feature vector: [hops, services, velocity, sensitivity, out_of_order]
    velocity = 1.0 / delta_t
    sensitivity = ROUTE_WEIGHTS.get(event.route, 0.5)
    distinct_services = len(tr.services_visited)
    service_index = SERVICE_ORDER.index(event.service) if event.service in SERVICE_ORDER else -1
    out_of_order = 0.0 if service_index == tr.last_service_index + 1 else 1.0
    tr.last_service_index = service_index

    feature_vector = np.array([[tr.hop_count, distinct_services, velocity, sensitivity, out_of_order]])
    score = float(model.decision_function(feature_vector)[0])
    tr.anomaly_score = score

    audit_entry = {
        "timestamp": event.timestamp,
        "run_id": run_id,
        "service": event.service,
        "route": event.route,
        "score": round(score, 4),
        "hop_count": tr.hop_count,
        "action": "none"
    }

    # Keep a simple deterministic escalation threshold alongside the model score.
    rapid_cross_service = (
        tr.hop_count >= 2
        and distinct_services >= 2
        and velocity > 0.05
        and sensitivity >= 0.8
    )
    if (score < -0.15 or rapid_cross_service or out_of_order == 1.0) and tr.hop_count >= 2 and not tr.contained:
        if defender_mode == "active":
            tr.contained = True
            tr.containment_time = now
            audit_entry["action"] = "revoke_triggered"

            # Revoke every downstream role concurrently; this is best-effort local containment.
            try:
                async with httpx.AsyncClient(timeout=0.1) as client:
                    await asyncio.gather(
                        client.post(IDENTITY_URL, json={"run_id": run_id}, headers={"X-Control-Token": CONTROL_TOKEN}),
                        client.post(WORKFLOW_URL, json={"run_id": run_id}, headers={"X-Control-Token": CONTROL_TOKEN}),
                        client.post(RECORDS_URL, json={"run_id": run_id}, headers={"X-Control-Token": CONTROL_TOKEN}),
                    )
            except Exception:
                pass
        else:
            audit_entry["action"] = "observed_only"

    audit_trail.append(audit_entry)
    return {"status": "processed", "score": score, "contained": tr.contained}

@app.get("/status")
async def get_status():
    latest_run = list(trackers.values())[-1] if trackers else None
    if not latest_run:
        return {
            "state": "IDLE",
            "active_run_id": None,
            "anomaly_score": 0.0,
            "contained": False,
            "recent_events": audit_trail[-10:]
        }

    return {
        "state": "CONTAINED" if latest_run.contained else ("EVALUATING" if latest_run.hop_count > 1 else "NORMAL"),
        "active_run_id": latest_run.run_id,
        "hop_count": latest_run.hop_count,
        "distinct_services": len(latest_run.services_visited),
        "anomaly_score": round(latest_run.anomaly_score, 4),
        "contained": latest_run.contained,
        "recent_events": audit_trail[-10:]
    }

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    status = await get_status()
    state_color = "#dc2626" if status["state"] == "CONTAINED" else ("#16a34a" if status["state"] == "NORMAL" else "#eab308")
    rows = "".join([
        f"<tr><td>{e.get('timestamp','')}</td><td>{e.get('run_id','')}</td><td>{e.get('service','')}</td><td>{e.get('route','')}</td><td>{e.get('score','')}</td><td><b>{e.get('action','')}</b></td></tr>"
        for e in reversed(status.get("recent_events", []))
    ])

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Praetorian AI Defender Dashboard</title>
        <meta http-equiv="refresh" content="2">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }}
            .card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
            .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-weight: bold; background: {state_color}; color: white; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
            th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; }}
            th {{ background: #0f172a; }}
        </style>
    </head>
    <body>
        <h1>Praetorian Micro-Defender: Real-time Containment</h1>
        <div class="card">
            <h2>Current State: <span class="badge">{status['state']}</span></h2>
            <p><b>Active Run ID:</b> {status['active_run_id'] or 'None'}</p>
            <p><b>Anomaly Score:</b> {status['anomaly_score']}</p>
            <p><b>Hops Observed:</b> {status.get('hop_count', 0)}</p>
        </div>
        <div class="card">
            <h3>Recent Telemetry & Containment Actions</h3>
            <table>
                <tr><th>Time</th><th>Run ID</th><th>Service</th><th>Route</th><th>Anomaly Score</th><th>Action</th></tr>
                {rows}
            </table>
        </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=DEFENDER_PORT)
