#!/usr/bin/env python3
"""
ViaDigiTech SOC — Module SQLite (V11.0)
Stockage persistant : audit_actions, score_history, threat_patterns.
Migration transparente depuis audit_actions.csv et threat_patterns.json.
"""

import os
import csv
import json
import sqlite3
from datetime import datetime

DB_PATH     = "/home/ubuntu/secops/soc.db"
AUDIT_LOG   = "/home/ubuntu/secops/audit_actions.csv"
THREAT_FILE = "/home/ubuntu/secops/threat_patterns.json"


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS audit_actions (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      TEXT NOT NULL,
                ip      TEXT NOT NULL,
                action  TEXT NOT NULL,
                score   INTEGER DEFAULT 0,
                reason  TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_audit_ip ON audit_actions(ip);
            CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_actions(ts);

            CREATE TABLE IF NOT EXISTS score_history (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      TEXT NOT NULL,
                ip      TEXT NOT NULL,
                score   INTEGER NOT NULL,
                action  TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_score_ip ON score_history(ip);
            CREATE INDEX IF NOT EXISTS idx_score_ts ON score_history(ts);

            CREATE TABLE IF NOT EXISTS threat_patterns (
                ip          TEXT PRIMARY KEY,
                first_seen  TEXT,
                bans        INTEGER DEFAULT 0,
                score_max   INTEGER DEFAULT 0,
                is_subnet   INTEGER DEFAULT 0,
                extra       TEXT DEFAULT '{}'
            );
        """)
    _migrate_if_needed()


def _migrate_if_needed():
    """Importe CSV/JSON existants si la DB est vide (premier lancement)."""
    with get_conn() as conn:
        audit_count = conn.execute("SELECT COUNT(*) FROM audit_actions").fetchone()[0]
    if audit_count > 0:
        return

    # Migrate audit CSV → SQLite
    if os.path.exists(AUDIT_LOG):
        rows = []
        try:
            with open(AUDIT_LOG) as f:
                for row in csv.DictReader(f):
                    rows.append((
                        row.get("timestamp", ""),
                        row.get("ip", ""),
                        row.get("action", ""),
                        int(row.get("score", 0) or 0),
                        row.get("reason", ""),
                    ))
        except Exception:
            pass
        if rows:
            with get_conn() as conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO audit_actions(ts,ip,action,score,reason) VALUES(?,?,?,?,?)",
                    rows,
                )

    # Migrate threat_patterns JSON → SQLite
    if os.path.exists(THREAT_FILE):
        try:
            with open(THREAT_FILE) as f:
                patterns = json.load(f)
            rows = []
            for ip, data in patterns.items():
                is_subnet = 1 if "/" in ip else 0
                rows.append((
                    ip,
                    data.get("first_seen", ""),
                    data.get("bans", 0),
                    data.get("score_max", 0) if not is_subnet else 0,
                    is_subnet,
                    json.dumps(data),
                ))
            with get_conn() as conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO threat_patterns(ip,first_seen,bans,score_max,is_subnet,extra) VALUES(?,?,?,?,?,?)",
                    rows,
                )
        except Exception:
            pass

    print("[soc_db] Migration initiale terminée.")


# ─────────────────────────────────────────
# AUDIT ACTIONS
# ─────────────────────────────────────────

def db_write_audit(ip, action, score, reason=""):
    """Enregistre une action dans SQLite ET dans le CSV legacy."""
    ts = datetime.now().isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_actions(ts,ip,action,score,reason) VALUES(?,?,?,?,?)",
            (ts, ip, action, score, reason),
        )
    # CSV legacy pour compatibilité dashboard existant
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    header = not os.path.exists(AUDIT_LOG)
    with open(AUDIT_LOG, "a") as f:
        if header:
            f.write("timestamp,ip,action,score,reason\n")
        f.write(f"{ts},{ip},{action},{score},{reason}\n")


def db_get_audit(ip=None, limit=200, since_hours=None):
    """Retourne les actions, optionnellement filtrées par IP ou fenêtre temporelle."""
    clauses, params = [], []
    if ip:
        clauses.append("ip=?")
        params.append(ip)
    if since_hours:
        from datetime import timedelta
        since = (datetime.now() - timedelta(hours=since_hours)).isoformat()
        clauses.append("ts >= ?")
        params.append(since)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT ts,ip,action,score,reason FROM audit_actions {where} ORDER BY ts DESC LIMIT ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────
# SCORE HISTORY
# ─────────────────────────────────────────

def db_add_score_history(ip, score, action=""):
    ts = datetime.now().isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO score_history(ts,ip,score,action) VALUES(?,?,?,?)",
            (ts, ip, score, action),
        )


def db_get_score_history(ip, limit=30):
    """Retourne l'historique de scores d'une IP, du plus ancien au plus récent."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ts, score, action FROM score_history WHERE ip=? ORDER BY ts DESC LIMIT ?",
            (ip, limit),
        ).fetchall()
    return [{"ts": r["ts"], "score": r["score"], "action": r["action"]} for r in reversed(rows)]


# ─────────────────────────────────────────
# STATS
# ─────────────────────────────────────────

def db_get_stats(hours=24):
    """Stats globales pour le dashboard et les alertes de seuil."""
    from datetime import timedelta
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    with get_conn() as conn:
        total_bans = conn.execute(
            "SELECT COUNT(*) FROM audit_actions WHERE action LIKE 'BAN%' AND ts >= ?", (since,)
        ).fetchone()[0]
        avg_score = conn.execute(
            "SELECT AVG(score) FROM audit_actions WHERE ts >= ?", (since,)
        ).fetchone()[0] or 0
        top_ips = conn.execute(
            "SELECT ip, COUNT(*) AS cnt FROM audit_actions WHERE ts >= ? GROUP BY ip ORDER BY cnt DESC LIMIT 10",
            (since,),
        ).fetchall()
    return {
        "total_bans": total_bans,
        "avg_score": round(float(avg_score), 1),
        "top_ips": [{"ip": r["ip"], "count": r["cnt"]} for r in top_ips],
    }


# ─────────────────────────────────────────
# THREAT PATTERNS
# ─────────────────────────────────────────

_BAN_ACTIONS = {"BAN_AUTO", "BAN_OLLAMA", "BAN_TEMP", "BAN_GEO"}


def db_update_threat_pattern(ip, action, score):
    """Upsert threat pattern (IP individuelle ou subnet /24) dans SQLite."""
    is_subnet = 1 if "/" in ip else 0
    now_date = datetime.now().isoformat()[:10]
    now_ts   = datetime.now().isoformat()[:16]
    is_ban   = action in _BAN_ACTIONS

    with get_conn() as conn:
        row = conn.execute(
            "SELECT bans, score_max, extra FROM threat_patterns WHERE ip=?", (ip,)
        ).fetchone()
        if row:
            extra        = json.loads(row["extra"] or "{}")
            new_bans     = row["bans"] + (1 if is_ban else 0)
            new_score    = max(row["score_max"] or 0, score)
            if not is_subnet:
                acts = extra.get("actions", [])
                acts.append({"ts": now_ts, "action": action})
                extra["actions"] = acts[-10:]
            conn.execute(
                "UPDATE threat_patterns SET bans=?, score_max=?, extra=? WHERE ip=?",
                (new_bans, new_score, json.dumps(extra), ip),
            )
        else:
            extra = {} if is_subnet else {"actions": [{"ts": now_ts, "action": action}]}
            conn.execute(
                "INSERT INTO threat_patterns(ip,first_seen,bans,score_max,is_subnet,extra) "
                "VALUES(?,?,?,?,?,?)",
                (ip, now_date, int(is_ban), score, is_subnet, json.dumps(extra)),
            )


def db_get_threat_pattern(ip):
    """Retourne le profil complet d'une IP depuis SQLite (avec subnet_info)."""
    subnet = ".".join(ip.split(".")[:3]) + ".0/24" if "/" not in ip else None

    with get_conn() as conn:
        row        = conn.execute("SELECT * FROM threat_patterns WHERE ip=?", (ip,)).fetchone()
        subnet_row = conn.execute("SELECT * FROM threat_patterns WHERE ip=?", (subnet,)).fetchone() if subnet else None

    if not row:
        return {}

    result = json.loads(row["extra"] or "{}")
    result.update({"first_seen": row["first_seen"], "bans": row["bans"], "score_max": row["score_max"]})

    if subnet_row:
        sub = json.loads(subnet_row["extra"] or "{}")
        sub.update({"first_seen": subnet_row["first_seen"], "bans": subnet_row["bans"]})
        result["subnet_info"] = sub

    return result


def db_purge_old_patterns(days=90):
    """Supprime les IPs inactives depuis plus de N jours."""
    from datetime import timedelta
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()[:10]
    with get_conn() as conn:
        deleted = conn.execute(
            "DELETE FROM threat_patterns WHERE first_seen < ? AND bans = 0", (cutoff,)
        ).rowcount
    return deleted


# Initialisation au chargement du module
init_db()
