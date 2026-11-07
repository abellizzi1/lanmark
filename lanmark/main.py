import asyncio
import contextlib
import hmac
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import CollectorRegistry, Gauge, generate_latest
from prometheus_client.parser import text_string_to_metric_families

from .config import load_settings
from .models import AlertBatch, Approval, Sample, Scan
from .store import Store

log = logging.getLogger("lanmark")
bearer = HTTPBearer(auto_error=False)


def create_app():
    settings = load_settings()
    api_token = os.getenv("LANMARK_API_TOKEN", "")
    agent_token = os.getenv("LANMARK_AGENT_TOKEN", "")
    if min(len(api_token), len(agent_token)) < 32 or hmac.compare_digest(api_token, agent_token):
        raise RuntimeError("Set distinct LANMARK_API_TOKEN and LANMARK_AGENT_TOKEN values of at least 32 characters")
    store = Store(os.getenv("DATABASE_PATH", "/data/lanmark.db"), settings)

    def admin(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if not credentials or not hmac.compare_digest(credentials.credentials.encode(), api_token.encode()):
            raise HTTPException(401, "An administrator bearer token is required", headers={"WWW-Authenticate": "Bearer"})

    def agent(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if not credentials or not hmac.compare_digest(credentials.credentials.encode(), agent_token.encode()):
            raise HTTPException(401, "An agent bearer token is required", headers={"WWW-Authenticate": "Bearer"})

    async def probe(client, target):
        response = await client.get(os.getenv("BLACKBOX_URL", "http://blackbox:9115") + "/probe", params={"module": target.module, "target": target.address})
        response.raise_for_status()
        values = {}
        for family in text_string_to_metric_families(response.text):
            for sample in family.samples:
                if sample.name == "probe_icmp_duration_seconds" and sample.labels.get("phase") == "rtt":
                    values["rtt"] = sample.value
                elif not sample.labels:
                    values[sample.name] = sample.value
        if "probe_success" not in values:
            raise ValueError("Exporter response has no probe_success")
        success = values["probe_success"] == 1
        latency = values.get("rtt") if target.module == "icmp_ipv4" else values.get("probe_duration_seconds")
        return Sample(target=target.name, kind=target.kind, success=success, latency_seconds=latency if success else None)

    async def collect(client):
        results = await asyncio.gather(*(probe(client, t) for t in settings.targets), return_exceptions=True)
        samples = []
        for target, result in zip(settings.targets, results):
            if isinstance(result, Exception):
                # An exporter error is missing telemetry, not a failed network probe.
                log.warning("Exporter unavailable for target %s (%s)", target.name, type(result).__name__)
                continue
            samples.append(result)
        if samples:
            store.ingest(Scan(source="cluster", scan_id=uuid.uuid4().hex, scan_ok=False, samples=samples), time.time())

    async def deliver(client):
        webhook = os.getenv("NOTIFICATION_WEBHOOK_URL", "")
        if not webhook:
            return
        now = time.time()
        for row in store.query("SELECT * FROM outbox WHERE delivered_at IS NULL AND next_attempt<=? ORDER BY id LIMIT 20", (now,)):
            try:
                response = await client.post(webhook, json=json.loads(row["payload"]))
                response.raise_for_status()
            except (httpx.HTTPError, ValueError):
                # Never log secret webhook URLs or credentials.
                with store.connection() as db:
                    db.execute("UPDATE outbox SET attempts=attempts+1,next_attempt=? WHERE id=?", (now + min(3600, 2 ** min(row["attempts"] + 1, 12)), row["id"]))
                log.warning("Notification delivery failed for outbox item %s; retry scheduled", row["id"])
            else:
                with store.connection() as db:
                    db.execute("UPDATE outbox SET delivered_at=? WHERE id=?", (now, row["id"]))

    async def worker():
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            while True:
                try:
                    await collect(client)
                    await deliver(client)
                    store.prune(time.time())
                except Exception:
                    log.exception("Collection cycle failed; next cycle will retry")
                await asyncio.sleep(settings.interval_seconds)

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(worker())
        yield
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    app = FastAPI(title="Lanmark", version="0.1.0", lifespan=lifespan)

    @app.get("/healthz", include_in_schema=False)
    def health():
        store.query("SELECT 1")
        return {"status": "ok"}

    @app.get("/v1/devices", dependencies=[Depends(admin)])
    def devices(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        return store.query("SELECT d.*,EXISTS(SELECT 1 FROM sightings s WHERE s.mac=d.mac AND s.online=1) AS online FROM devices d ORDER BY last_seen DESC LIMIT ? OFFSET ?", (limit, offset))

    @app.get("/v1/devices/{mac}/history", dependencies=[Depends(admin)])
    def history(mac: str, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        return store.query("SELECT * FROM events WHERE mac=? ORDER BY id DESC LIMIT ? OFFSET ?", (mac.lower(), limit, offset))

    @app.put("/v1/devices/{mac}/approval", dependencies=[Depends(admin)])
    def approval(mac: str, value: Approval):
        if not store.approve(mac.lower(), value.approved, value.name, time.time()):
            raise HTTPException(404, "Device not found")
        return {"approved": value.approved, "name": value.name}

    @app.get("/v1/incidents", dependencies=[Depends(admin)])
    def incidents(active_only: bool = False, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        rows = store.query("SELECT * FROM incidents WHERE (?=0 OR resolved_at IS NULL) ORDER BY updated_at DESC LIMIT ? OFFSET ?", (int(active_only), limit, offset))
        return [row | {"evidence": json.loads(row["evidence"])} for row in rows]

    @app.get("/v1/samples", dependencies=[Depends(admin)])
    def samples(source: str | None = None, target: str | None = None, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        return store.query("SELECT * FROM samples WHERE (? IS NULL OR source=?) AND (? IS NULL OR target=?) ORDER BY id DESC LIMIT ? OFFSET ?", (source, source, target, target, limit, offset))

    @app.get("/v1/agents", dependencies=[Depends(admin)])
    def agents():
        return {"expected": settings.expected_agents, "observed": store.query("SELECT * FROM agents")}

    @app.post("/v1/scans", dependencies=[Depends(agent)])
    def scans(scan: Scan):
        if scan.source not in settings.expected_agents or scan.source == "cluster":
            raise HTTPException(422, "Source must match a configured expected_agents entry")
        if not scan.scan_ok and scan.devices:
            raise HTTPException(422, "A failed scan cannot supply device observations")
        return {"accepted": store.ingest(scan, time.time())}

    @app.post("/v1/alerts", dependencies=[Depends(admin)])
    def alerts(batch: AlertBatch):
        now = time.time()
        with store.connection() as db:
            for alert in batch.alerts:
                key = "alert:" + alert.fingerprint
                if alert.status == "resolved":
                    store.resolve(db, key, now)
                else:
                    store.incident(db, key, "prometheus_alert", alert.annotations.get("summary", alert.labels.get("alertname", "Network alert"))[:2000], alert.model_dump(), now)
        return {"received": len(batch.alerts)}

    @app.get("/metrics", dependencies=[Depends(admin)], include_in_schema=False)
    def metrics():
        registry = CollectorRegistry()

        def gauge(name, help_text, labels, rows):
            metric = Gauge(name, help_text, labels, registry=registry)
            for keys, value in rows:
                metric.labels(*keys).set(value) if labels else metric.set(value)

        inventory = store.query("SELECT d.mac,d.approved,EXISTS(SELECT 1 FROM sightings s WHERE s.mac=d.mac AND s.online=1) AS online FROM devices d")
        gauge("lanmark_devices", "Inventory size by approval state", ["approved"], [([str(bool(a)).lower()], sum(d["approved"] == a for d in inventory)) for a in (0, 1)])
        gauge("lanmark_device_online", "Last observed device presence; check scan freshness", ["mac", "approved"], [([d["mac"], str(bool(d["approved"])).lower()], d["online"]) for d in inventory])
        agent_rows = {r["source"]: r for r in store.query("SELECT * FROM agents")}
        sources = set(settings.expected_agents) | set(agent_rows)
        for name, column in [("heartbeat", "heartbeat"), ("scan_success", "scan_success")]:
            gauge(f"lanmark_agent_{name}_timestamp_seconds", f"Last agent {name} timestamp, zero until observed", ["source"], [([s], agent_rows.get(s, {}).get(column, 0)) for s in sorted(sources)])
        rows = store.query("SELECT s.* FROM samples s JOIN (SELECT MAX(id) id FROM samples GROUP BY source,target) latest ON s.id=latest.id")
        label_names = ["source", "target", "kind"]
        for name, column in [("probe_success", "success"), ("latency_seconds", "latency"), ("loss_ratio", "loss"), ("jitter_seconds", "jitter"), ("sample_timestamp_seconds", "at")]:
            gauge(f"lanmark_{name}", f"Latest {name} per source and target", label_names, [([r["source"], r["target"], r["kind"]], r[column]) for r in rows if r[column] is not None and (column not in ("latency", "jitter") or r["success"])])
        # Emit zero timestamps for configured but never-observed cluster targets.
        freshness = Gauge("lanmark_expected_target_timestamp_seconds", "Last observation of each configured cluster target", ["target"], registry=registry)
        for t in settings.targets:
            freshness.labels(t.name).set(max((r["at"] for r in rows if r["source"] == "cluster" and r["target"] == t.name), default=0))
        active = store.query("SELECT kind,COUNT(*) count FROM incidents WHERE resolved_at IS NULL GROUP BY kind")
        counts = {r["kind"]: r["count"] for r in active}
        gauge("lanmark_active_incidents", "Unresolved incidents", ["kind"], [([k], counts.get(k, 0)) for k in {"new_device", "connectivity", "latency_anomaly", "traffic_spike", "device_activity", "prometheus_alert"}])
        traffic_rows = store.query("SELECT t.* FROM traffic t JOIN (SELECT MAX(id) id FROM traffic GROUP BY source,interface) latest ON t.id=latest.id")
        for direction in ("rx", "tx"):
            gauge(f"lanmark_interface_{direction}_bytes_per_second", "Agent host interface throughput, not total LAN usage", ["source", "interface"], [([r["source"], r["interface"]], r[direction]) for r in traffic_rows if time.time() - r["at"] < 180])
        pending = store.query("SELECT COUNT(*) count FROM outbox WHERE delivered_at IS NULL")[0]["count"]
        gauge("lanmark_notifications_pending", "Undelivered webhook events; configure webhook to drain", [], [([], pending)])
        return Response(generate_latest(registry), media_type="text/plain; version=0.0.4")

    return app


app = create_app()
