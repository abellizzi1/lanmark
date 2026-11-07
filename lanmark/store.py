import json
import sqlite3
from statistics import median
from contextlib import contextmanager
from pathlib import Path

from .analysis import explain, latency_anomaly
from .config import Settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
 mac TEXT PRIMARY KEY, ip TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
 approved INTEGER NOT NULL DEFAULT 0, first_seen REAL NOT NULL, last_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sightings (
 mac TEXT NOT NULL, source TEXT NOT NULL, ip TEXT NOT NULL, last_seen REAL NOT NULL,
 online INTEGER NOT NULL, PRIMARY KEY(mac,source));
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY, at REAL NOT NULL, mac TEXT NOT NULL,
 source TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_mac_at ON events(mac,at);
CREATE TABLE IF NOT EXISTS agents (
 source TEXT PRIMARY KEY, heartbeat REAL NOT NULL, scan_success REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS scans (
 source TEXT NOT NULL, scan_id TEXT NOT NULL, at REAL NOT NULL, PRIMARY KEY(source,scan_id));
CREATE TABLE IF NOT EXISTS samples (
 id INTEGER PRIMARY KEY, at REAL NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL,
 kind TEXT NOT NULL, success INTEGER NOT NULL, latency REAL, loss REAL, jitter REAL);
CREATE INDEX IF NOT EXISTS samples_lookup ON samples(source,target,at);
CREATE TABLE IF NOT EXISTS traffic (
 id INTEGER PRIMARY KEY, at REAL NOT NULL, source TEXT NOT NULL, interface TEXT NOT NULL,
 rx REAL NOT NULL, tx REAL NOT NULL);
CREATE INDEX IF NOT EXISTS traffic_lookup ON traffic(source,interface,at);
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY, incident_key TEXT NOT NULL, kind TEXT NOT NULL,
 summary TEXT NOT NULL, evidence TEXT NOT NULL, opened_at REAL NOT NULL,
 updated_at REAL NOT NULL, resolved_at REAL, occurrences INTEGER NOT NULL DEFAULT 1);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_active ON incidents(incident_key) WHERE resolved_at IS NULL;
CREATE TABLE IF NOT EXISTS outbox (
 id INTEGER PRIMARY KEY, payload TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt REAL NOT NULL, delivered_at REAL);
"""


class Store:
    def __init__(self, path: str, settings: Settings):
        self.path, self.settings = path, settings
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript(SCHEMA)
            db.execute("PRAGMA user_version=1")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def query(self, sql, args=()):
        with self.connection() as db:
            return [dict(r) for r in db.execute(sql, args)]

    def notify(self, db, payload, now):
        db.execute("INSERT INTO outbox(payload,next_attempt) VALUES(?,?)", (json.dumps(payload), now))

    def incident(self, db, key, kind, summary, evidence, now):
        active = db.execute("SELECT id FROM incidents WHERE incident_key=? AND resolved_at IS NULL", (key,)).fetchone()
        if active:
            db.execute("UPDATE incidents SET updated_at=?,summary=?,evidence=?,occurrences=occurrences+1 WHERE id=?",
                       (now, summary, json.dumps(evidence), active["id"]))
            return
        db.execute("INSERT INTO incidents(incident_key,kind,summary,evidence,opened_at,updated_at) VALUES(?,?,?,?,?,?)",
                   (key, kind, summary, json.dumps(evidence), now, now))
        self.notify(db, {"event": "incident_opened", "key": key, "kind": kind, "summary": summary, "evidence": evidence}, now)

    def resolve(self, db, key, now):
        changed = db.execute("UPDATE incidents SET resolved_at=?,updated_at=? WHERE incident_key=? AND resolved_at IS NULL", (now, now, key)).rowcount
        if changed:
            self.notify(db, {"event": "incident_resolved", "key": key}, now)

    def ingest(self, scan, now):
        with self.connection() as db:
            # One transaction includes idempotency, inventory, samples and outbox.
            if not db.execute("INSERT OR IGNORE INTO scans VALUES(?,?,?)", (scan.source, scan.scan_id, now)).rowcount:
                return False
            db.execute("INSERT INTO agents(source,heartbeat,scan_success) VALUES(?,?,?) ON CONFLICT(source) DO UPDATE SET heartbeat=excluded.heartbeat,scan_success=CASE WHEN excluded.scan_success>0 THEN excluded.scan_success ELSE agents.scan_success END",
                       (scan.source, now, now if scan.scan_ok else 0))
            if scan.scan_ok:
                for d in scan.devices:
                    old = db.execute("SELECT * FROM devices WHERE mac=?", (d.mac,)).fetchone()
                    sighting = db.execute("SELECT * FROM sightings WHERE mac=? AND source=?", (d.mac, scan.source)).fetchone()
                    db.execute("INSERT INTO devices(mac,ip,first_seen,last_seen) VALUES(?,?,?,?) ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,last_seen=excluded.last_seen", (d.mac, d.ip, now, now))
                    if not old:
                        self.incident(db, f"device:{d.mac}", "new_device", f"Unapproved device {d.mac} appeared at {d.ip}.", {"mac": d.mac, "ip": d.ip, "source": scan.source}, now)
                    elif not old["approved"]:
                        self.incident(db, f"device:{d.mac}", "new_device", f"Unapproved device {d.mac} is present at {d.ip}.", {"mac": d.mac, "ip": d.ip, "source": scan.source}, now)
                    if not sighting or not sighting["online"]:
                        db.execute("INSERT INTO events(at,mac,source,kind,detail) VALUES(?,?,?,?,?)", (now, d.mac, scan.source, "online", d.ip))
                        reconnects = db.execute("SELECT COUNT(*) FROM events WHERE mac=? AND source=? AND kind='online' AND at>?", (d.mac, scan.source, now - 3600)).fetchone()[0]
                        if reconnects >= 6:
                            self.incident(db, f"activity:{scan.source}:{d.mac}", "device_activity", f"Device {d.mac} repeatedly reappeared on {scan.source}.", {"mac": d.mac, "source": scan.source, "appearances_in_hour": reconnects, "explanation": "Frequent presence changes can indicate link instability, sleep cycles, or intermittent ARP replies; they do not prove malicious activity."}, now)
                    if sighting and sighting["ip"] != d.ip:
                        db.execute("INSERT INTO events(at,mac,source,kind,detail) VALUES(?,?,?,?,?)", (now, d.mac, scan.source, "ip_changed", f"{sighting['ip']} -> {d.ip}"))
                    db.execute("INSERT INTO sightings VALUES(?,?,?,?,1) ON CONFLICT(mac,source) DO UPDATE SET ip=excluded.ip,last_seen=excluded.last_seen,online=1", (d.mac, scan.source, d.ip, now))
                # Failed scans never mark devices offline. Absence must be observed
                # during a successful scan after the configured grace period.
                gone = db.execute("SELECT mac,ip FROM sightings WHERE source=? AND online=1 AND last_seen<?", (scan.source, now - self.settings.offline_after_seconds)).fetchall()
                for d in gone:
                    db.execute("UPDATE sightings SET online=0 WHERE mac=? AND source=?", (d["mac"], scan.source))
                    db.execute("INSERT INTO events(at,mac,source,kind,detail) VALUES(?,?,?,?,?)", (now, d["mac"], scan.source, "offline", d["ip"]))
            explanation = explain([s.model_dump() for s in scan.samples])
            for sample in scan.samples:
                self.record_sample(db, scan.source, sample, now, explanation)
            if scan.traffic:
                traffic = scan.traffic
                baseline = [r[0] for r in db.execute("SELECT rx+tx FROM traffic WHERE source=? AND interface=? ORDER BY id DESC LIMIT ?", (scan.source, traffic.interface, self.settings.baseline_samples))]
                if len(baseline) >= 30:
                    center = median(baseline)
                    mad = median(abs(v - center) for v in baseline)
                    threshold = center + max(6 * 1.4826 * mad, 1_000_000, center * 2)
                    key = f"traffic:{scan.source}:{traffic.interface}"
                    if traffic.rx_bytes_per_second + traffic.tx_bytes_per_second > threshold:
                        self.incident(db, key, "traffic_spike", f"Host interface traffic on {scan.source}/{traffic.interface} exceeds its baseline.", {"source": scan.source, "interface": traffic.interface, "median_bytes_per_second": center, "threshold_bytes_per_second": threshold, "observed_bytes_per_second": traffic.rx_bytes_per_second + traffic.tx_bytes_per_second, "scope": "Agent host only; other LAN devices are not measured."}, now)
                    else:
                        self.resolve(db, key, now)
                db.execute("INSERT INTO traffic(at,source,interface,rx,tx) VALUES(?,?,?,?,?)", (now, scan.source, traffic.interface, traffic.rx_bytes_per_second, traffic.tx_bytes_per_second))
            return True

    def record_sample(self, db, source, s, now, explanation):
        history = db.execute("SELECT success,latency FROM samples WHERE source=? AND target=? AND kind=? ORDER BY id DESC LIMIT ?", (source, s.target, s.kind, self.settings.baseline_samples)).fetchall()
        window = history[:19]
        loss = s.loss_ratio if s.loss_ratio is not None else 1 - (int(s.success) + sum(r["success"] for r in window)) / (len(window) + 1)
        # Inter-sample absolute RTT difference, distinct from within-burst jitter.
        previous = history[0] if history else None
        jitter = s.jitter_seconds
        if jitter is None and s.success and s.latency_seconds is not None and previous and previous["success"] and previous["latency"] is not None:
            jitter = abs(s.latency_seconds - previous["latency"])
        evidence = {"source": source, "target": s.target, "kind": s.kind, "loss_ratio": loss, "explanation": explanation}
        outage_key = f"outage:{source}:{s.target}"
        if not s.success:
            self.incident(db, outage_key, "connectivity", f"{s.target} probe failed. {explanation}", evidence, now)
        else:
            self.resolve(db, outage_key, now)
        latency_key = f"latency:{source}:{s.target}"
        anomaly = latency_anomaly([r["latency"] for r in history if r["success"] and r["latency"] is not None], s.latency_seconds) if s.success and s.latency_seconds is not None else None
        if anomaly:
            self.incident(db, latency_key, "latency_anomaly", f"{s.target} latency exceeds its robust baseline. {explanation}", evidence | anomaly, now)
        elif s.success:
            self.resolve(db, latency_key, now)
        db.execute("INSERT INTO samples(at,source,target,kind,success,latency,loss,jitter) VALUES(?,?,?,?,?,?,?,?)", (now, source, s.target, s.kind, int(s.success), s.latency_seconds, loss, jitter))

    def approve(self, mac, approved, name, now):
        with self.connection() as db:
            if not db.execute("UPDATE devices SET approved=?,name=? WHERE mac=?", (int(approved), name, mac)).rowcount:
                return False
            db.execute("INSERT INTO events(at,mac,source,kind,detail) VALUES(?,?,?,?,?)", (now, mac, "admin", "approved" if approved else "unapproved", name))
            if approved:
                self.resolve(db, f"device:{mac}", now)
            return True

    def prune(self, now):
        cutoff = now - self.settings.retention_days * 86400
        with self.connection() as db:
            for table, column in [("samples", "at"), ("events", "at"), ("scans", "at"), ("traffic", "at")]:
                db.execute(f"DELETE FROM {table} WHERE {column}<?", (cutoff,))
            db.execute("DELETE FROM incidents WHERE resolved_at<?", (cutoff,))
            db.execute("DELETE FROM outbox WHERE delivered_at<?", (cutoff,))
            quiet = db.execute("SELECT incident_key FROM incidents WHERE kind='device_activity' AND resolved_at IS NULL AND updated_at<?", (now - 3600,)).fetchall()
            for row in quiet:
                self.resolve(db, row["incident_key"], now)

    def backup(self, path):
        with self.connection() as db, sqlite3.connect(path) as destination:
            db.backup(destination)
