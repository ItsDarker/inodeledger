"""Transactional SQLite ledger and regenerable, hash-chained exports."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
from urllib.parse import quote
import uuid

from .metadata import canonical, beneath, capture, changed, collect, reject_links, native_path


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def default_home():
    return Path(os.environ.get("INODELEDGER_HOME", str(Path.home() / ".inodeledger")))


class Ledger:
    def __init__(self, home=None):
        self.home = Path(canonical(home or default_home()))
        reject_links(self.home)
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in ("history.sqlite", "history.sqlite-wal", "history.sqlite-shm"):
            reject_links(self.home / name)
        self.db = sqlite3.connect(self.home / "history.sqlite", timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS roots(path TEXT PRIMARY KEY,enabled INTEGER NOT NULL,last_scan TEXT);
        CREATE TABLE IF NOT EXISTS objects(id TEXT PRIMARY KEY,root TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS paths(path TEXT PRIMARY KEY,object_id TEXT NOT NULL,root TEXT NOT NULL,metadata TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,time TEXT NOT NULL,object_id TEXT,path TEXT,kind TEXT NOT NULL,payload TEXT NOT NULL,previous TEXT NOT NULL,hash TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS events_object ON events(object_id,seq);
        CREATE INDEX IF NOT EXISTS events_time ON events(time);
        CREATE INDEX IF NOT EXISTS paths_root ON paths(root);
        CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY,name TEXT NOT NULL,root TEXT NOT NULL,time TEXT NOT NULL,complete INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS entries(snapshot_id TEXT NOT NULL,path TEXT NOT NULL,object_id TEXT NOT NULL,metadata TEXT NOT NULL,PRIMARY KEY(snapshot_id,path));
        CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY,time TEXT NOT NULL,status TEXT NOT NULL,payload TEXT NOT NULL);
        """)
        self.db.execute("INSERT OR IGNORE INTO settings VALUES('host_id',?)", (str(uuid.uuid4()),))
        self.db.execute("INSERT OR IGNORE INTO settings VALUES('schema_version','1')")
        self.db.commit()

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def event(self, kind, path=None, object_id=None, before=None, after=None, **extra):
        stamp, identifier = now(), str(uuid.uuid4())
        payload = {"id": identifier, "time": stamp, "kind": kind, "path": path,
                   "object_id": object_id, "before": before, "after": after,
                   "source": "reconciliation", "actor": None, "process": None,
                   "confidence": "Observed state; transition time and actor unknown",
                   "host_id": self.db.execute("SELECT value FROM settings WHERE key='host_id'").fetchone()[0], **extra}
        previous = self.db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        previous = previous[0] if previous else "0" * 64
        body = packed(payload)
        digest = hashlib.sha256((previous + body).encode()).hexdigest()
        self.db.execute("INSERT INTO events(id,time,object_id,path,kind,payload,previous,hash) VALUES(?,?,?,?,?,?,?,?)",
                        (identifier, stamp, object_id, path, kind, body, previous, digest))
        return payload

    def add_root(self, path):
        path = canonical(path)
        reject_links(path)
        if not Path(path).is_dir():
            raise ValueError("Monitored root must be an existing directory")
        if beneath(self.home, path) or beneath(path, self.home):
            raise ValueError("Monitored roots and ledger storage must be separate")
        for row in self.db.execute("SELECT path FROM roots WHERE enabled=1"):
            if row[0] != path and (beneath(path, row[0]) or beneath(row[0], path)):
                raise ValueError("Overlapping monitored roots are not supported")
        with self.transaction():
            self.db.execute("INSERT INTO roots VALUES(?,1,NULL) ON CONFLICT(path) DO UPDATE SET enabled=1", (path,))
        return self.reconcile(path)

    def roots(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM roots ORDER BY path")]

    def remove_root(self, path):
        with self.transaction():
            self.db.execute("UPDATE roots SET enabled=0 WHERE path=?", (canonical(path),))
            self.event("monitoring_disabled", canonical(path))

    def reconcile(self, root, snapshot_name=None):
        root = canonical(root)
        # Serialize scans across GUI/CLI/agent so older scans cannot overwrite newer ones.
        with self.transaction():
            config = self.db.execute("SELECT * FROM roots WHERE path=? AND enabled=1", (root,)).fetchone()
            if not config:
                raise ValueError("Directory is not actively monitored")
            current, errors = collect(root)
            old = {r["path"]: dict(r) for r in self.db.execute("SELECT * FROM paths WHERE root=?", (root,))}
            identities = {}
            for row in old.values():
                m = json.loads(row["metadata"])
                identities.setdefault((m["device"], m["inode"], m["kind"]), []).append(row)
            seen_ids, changes = {}, 0
            for path, m in sorted(current.items()):
                key = (m["device"], m["inode"], m["kind"])
                prior = old.get(path)
                before = json.loads(prior["metadata"]) if prior else None
                same = before and (before["device"], before["inode"], before["kind"]) == key
                if same and before.get("birthtime_ns") != m.get("birthtime_ns"):
                    same = False
                oid = prior["object_id"] if same else None
                alias = None
                if not oid:
                    # Only correlate a newly observed hard link when an existing alias
                    # still proves the identity. Disappeared inodes may have been reused.
                    for candidate in identities.get(key, []):
                        cm = current.get(candidate["path"])
                        if cm and (cm["device"], cm["inode"], cm["kind"]) == key and cm["links"] > 1:
                            oid, alias = candidate["object_id"], candidate["path"]
                            break
                    oid = oid or seen_ids.get(key) or str(uuid.uuid4())
                    self.db.execute("INSERT OR IGNORE INTO objects VALUES(?,?)", (oid, root))
                seen_ids[key] = oid
                fields = changed(before, m) if same else []
                kind = None
                if not prior:
                    kind = "baseline" if config["last_scan"] is None else "observed_new"
                elif not same:
                    kind = "replacement"
                elif fields:
                    kind = "permission_change" if "mode" in fields else "ownership_change" if "uid" in fields or "gid" in fields else "acl_change" if "xattrs" in fields else "metadata_change"
                if kind:
                    candidates = [r["path"] for r in identities.get(key, []) if r["path"] not in current]
                    self.event(kind, path, oid, before, m, changed_fields=fields,
                               possible_previous_paths=candidates if not same else [], verified_hardlink_alias=alias,
                               severity="high" if os.name == "posix" and m["mode"] & 0o4002 else "info")
                    changes += 1
                self.db.execute("INSERT INTO paths VALUES(?,?,?,?) ON CONFLICT(path) DO UPDATE SET object_id=excluded.object_id,metadata=excluded.metadata,root=excluded.root", (path, oid, root, packed(m)))
            for path, prior in old.items():
                if path not in current and not any(beneath(path, e["path"]) for e in errors):
                    self.event("observed_missing", path, prior["object_id"], json.loads(prior["metadata"]), None)
                    self.db.execute("DELETE FROM paths WHERE path=?", (path,))
                    changes += 1
            if errors:
                self.event("coverage_gap", root, errors=errors)
            self.db.execute("UPDATE roots SET last_scan=? WHERE path=?", (now(), root))
            sid = self._snapshot(root, snapshot_name or ("Initial baseline" if config["last_scan"] is None else "Reconciliation"), not errors) if snapshot_name or config["last_scan"] is None else None
        return {"root": root, "observed": len(current), "changes": changes, "errors": errors, "snapshot_id": sid}

    def _snapshot(self, root, name, complete=True):
        sid = str(uuid.uuid4())
        self.db.execute("INSERT INTO snapshots VALUES(?,?,?,?,?)", (sid, name, root, now(), int(complete)))
        self.db.execute("INSERT INTO entries SELECT ?,path,object_id,metadata FROM paths WHERE root=?", (sid, root))
        return sid

    def snapshots(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM snapshots ORDER BY time DESC")]

    def files(self, search="", limit=500, offset=0):
        rows = self.db.execute("SELECT * FROM paths WHERE instr(lower(path),lower(?))>0 ORDER BY path LIMIT ? OFFSET ?", (search, min(max(int(limit), 1), 5000), max(0, int(offset))))
        return [{**dict(r), "metadata": json.loads(r["metadata"])} for r in rows]

    def events(self, path=None, kind=None, limit=200, object_id=None):
        clauses, args = [], []
        for column, value in (("path", canonical(path) if path else None), ("kind", kind), ("object_id", object_id)):
            if value:
                clauses.append(column + "=?")
                args.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        args.append(min(max(int(limit), 1), 10000))
        return [json.loads(r[0]) for r in self.db.execute("SELECT payload FROM events" + where + " ORDER BY seq DESC LIMIT ?", args)]

    def diff(self, first, second):
        def entries(sid):
            if not self.db.execute("SELECT 1 FROM snapshots WHERE id=?", (sid,)).fetchone():
                raise ValueError("Unknown snapshot")
            return {r["path"]: json.loads(r["metadata"]) for r in self.db.execute("SELECT * FROM entries WHERE snapshot_id=?", (sid,))}
        a, b = entries(first), entries(second)
        return [{"path": p, "before": a.get(p), "after": b.get(p), "fields": changed(a[p], b[p]) if p in a and p in b else ["presence"]} for p in sorted(a.keys() | b.keys()) if p not in a or p not in b or changed(a[p], b[p])]

    def verify(self):
        previous, count = "0" * 64, 0
        for r in self.db.execute("SELECT * FROM events ORDER BY seq"):
            expected = hashlib.sha256((previous + r["payload"]).encode()).hexdigest()
            try:
                p = json.loads(r["payload"])
            except (ValueError, TypeError):
                return {"valid": False, "failed_sequence": r["seq"], "checked": count}
            if not isinstance(p, dict) or r["previous"] != previous or r["hash"] != expected or any(r[k] != p.get(k) for k in ("id", "time", "object_id", "path", "kind")):
                return {"valid": False, "failed_sequence": r["seq"], "checked": count}
            previous, count = expected, count + 1
        return {"valid": True, "checked": count, "head": previous, "limitation": "Local hash chain; cannot prove absence of tail deletion or privileged rewriting"}

    def materialize(self):
        """Atomic derived exports; SQLite remains the durable source of truth."""
        check = self.verify()
        if not check["valid"]:
            raise ValueError("Integrity failure; refusing to export")
        outputs = {}
        for r in self.db.execute("SELECT * FROM events ORDER BY seq"):
            p = json.loads(r["payload"])
            line = packed({"event": p, "previous": r["previous"], "hash": r["hash"]}) + "\n"
            journal = Path("events") / (p["time"][:10] + ".jsonl")
            outputs.setdefault(journal, []).append(line)
            if p["path"]:
                parts = [quote(part, safe="")[:80] + "~" + hashlib.sha256(part.encode()).hexdigest()[:12] for part in Path(p["path"]).parts]
                mirror = Path("hosts") / p["host_id"] / "mirror"
                for part in parts:
                    mirror /= part
                outputs.setdefault(mirror / "_history.audit.jsonl", []).append(line)
                text = f"{p['time']} | {p['kind']}\nPath: {p['path']}\nLast recorded: {packed(p['before'])}\nObserved: {packed(p['after'])}\nSource: {p['source']} | Actor: unknown\n\n"
                outputs.setdefault(mirror / "_history.txt", []).append(text)
        for relative, lines in outputs.items():
            target = native_path(self.home / relative)
            reject_links(target)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temp = target.with_name(target.name + "." + uuid.uuid4().hex + ".tmp")
            with temp.open("x", encoding="utf-8") as f:
                f.writelines(lines)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, target)
        return {"files_written": len(outputs), "directory": str(self.home)}

    def status(self):
        heartbeat = self.db.execute("SELECT value FROM settings WHERE key='agent_heartbeat'").fetchone()
        return {"platform": platform.system(), "coverage": "Reduced: periodic reconciliation only",
                "agent_last_heartbeat": heartbeat[0] if heartbeat else None,
                "actor_attribution": "unavailable", "store": str(self.home), "roots": self.roots(),
                "objects": self.db.execute("SELECT count(DISTINCT object_id) FROM paths").fetchone()[0],
                "paths": self.db.execute("SELECT count(*) FROM paths").fetchone()[0],
                "events": self.db.execute("SELECT count(*) FROM events").fetchone()[0],
                "gaps": self.db.execute("SELECT count(*) FROM events WHERE kind='coverage_gap'").fetchone()[0]}

    def stop_agent(self):
        with self.transaction():
            self.db.execute("INSERT OR REPLACE INTO settings VALUES('agent_stop','1')")
        return {"status": "Stop requested; agent will exit after its current cycle"}
