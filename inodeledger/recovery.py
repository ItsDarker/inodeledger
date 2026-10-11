"""Explicit historical mode previews; descriptor-based application on Linux only."""
import json
import os
import stat
import sys
import uuid

from .metadata import canonical, capture, reject_links
from .store import now, packed


def plan(ledger, snapshot_id):
    snapshot = ledger.db.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
    if not snapshot:
        raise ValueError("Unknown snapshot")
    operations, identities = [], {}
    for r in ledger.db.execute("SELECT * FROM entries WHERE snapshot_id=? ORDER BY path", (snapshot_id,)):
        target = json.loads(r["metadata"])
        item = {"path": r["path"], "object_id": r["object_id"], "target_mode": target["mode"], "target_octal": target["octal"], "status": "ready", "reasons": [], "expected": None}
        try:
            reject_links(r["path"])
            current = capture(r["path"])
            if current["mode"] == target["mode"]:
                continue
            item["expected"] = current
            if current["kind"] not in ("file", "directory"):
                item["reasons"].append("Unsupported object type")
            if any(current[k] != target[k] for k in ("device", "inode", "birthtime_ns", "kind")):
                item["reasons"].append("Object identity changed")
            indexed = ledger.db.execute("SELECT object_id FROM paths WHERE path=?", (r["path"],)).fetchone()
            if not indexed or indexed[0] != r["object_id"]:
                item["reasons"].append("Recorded object identity differs")
            if any(current[k] != target[k] for k in ("size", "mtime_ns")):
                item["reasons"].append("Content metadata changed since snapshot")
            if current["uid"] != target["uid"] or current["gid"] != target["gid"]:
                item["reasons"].append("Ownership changed since snapshot")
            if current["xattr_error"] or current["xattrs"] or target["xattrs"]:
                item["reasons"].append("Extended security metadata requires separate review; mode-only restoration refused")
        except (OSError, ValueError) as exc:
            item["reasons"].append(str(exc))
        if not snapshot["complete"]:
            item["reasons"].append("Snapshot has coverage gaps")
        if item["reasons"]:
            item["status"] = "blocked"
        identity = (target["device"], target["inode"], target["kind"])
        if identity in identities:
            prior = identities[identity]
            prior.setdefault("aliases", []).append(item["path"])
            if prior["target_mode"] != item["target_mode"] or item["status"] == "blocked":
                prior["status"] = "blocked"
                prior["reasons"].append("Hard-link aliases have conflicting evidence or a blocked target")
            continue
        identities[identity] = item
        operations.append(item)
    payload = {"id": str(uuid.uuid4()), "snapshot_id": snapshot_id, "root": snapshot["root"], "created": now(), "operations": operations,
               "scope": "Traditional permission mode only", "dry_run": True,
               "limitation": "Device/inode identity cannot exclude every inode reuse race; no privileged attribution"}
    with ledger.transaction():
        ledger.db.execute("INSERT INTO plans VALUES(?,?,?,?)", (payload["id"], now(), "preview", packed(payload)))
        ledger.event("recovery_plan_created", snapshot["root"], plan_id=payload["id"], source="recovery")
    return payload


def preview(ledger, plan_id):
    row = ledger.db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    if not row:
        raise ValueError("Unknown recovery plan")
    return {**json.loads(row["payload"]), "status": row["status"]}


def open_safely(path):
    """Open each absolute path component relative to a pinned, no-follow directory."""
    parts = canonical(path).split(os.sep)
    directory = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)


def apply(ledger, plan_id, confirm=False):
    if not confirm:
        raise ValueError("Recovery requires --confirm after reviewing the plan")
    if not sys.platform.startswith("linux"):
        raise ValueError("Recovery application requires Linux; Windows supports previews only")
    p = preview(ledger, plan_id)
    if p["status"] != "preview":
        raise ValueError("Plan has already been attempted; create a new plan")
    if any(op["status"] != "ready" for op in p["operations"]):
        raise ValueError("Plan contains blocked operations; application refused")
    if len(p["operations"]) > 256:
        raise ValueError("Application is limited to 256 unique objects per plan to bound open descriptors")
    # Refresh the pre-recovery snapshot source. The subsequent descriptor checks
    # still compare against the preview's expected state and refuse stale plans.
    ledger.reconcile(p["root"])
    descriptors, results = [], []
    # A DB write lock also prevents the agent changing indexed state mid-recovery.
    try:
        with ledger.transaction():
            for op in p["operations"]:
                fd = open_safely(op["path"])
                descriptors.append((op, fd))
                s, m = os.fstat(fd), op["expected"]
                expected = (m["device"], m["inode"], m["mode"], m["uid"], m["gid"], m["size"], m["mtime_ns"], m["ctime_ns"])
                actual = (s.st_dev, s.st_ino, stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                if actual != expected:
                    raise ValueError(f"State changed after preview: {op['path']}")
            rollback = ledger._snapshot(p["root"], "Before recovery " + plan_id)
            # Persist intent before any filesystem mutation, including exact live modes.
            ledger.event("recovery_started", p["root"], plan_id=plan_id, rollback_snapshot=rollback, operations=p["operations"], source="recovery")
            ledger.db.execute("UPDATE plans SET status='applying' WHERE id=?", (plan_id,))
        for op, fd in descriptors:
            try:
                # Recheck immediately before use. Concurrent writers can still race;
                # recovery should run in a maintenance window.
                s = os.fstat(fd)
                if s.st_ctime_ns != op["expected"]["ctime_ns"]:
                    raise ValueError("Object changed during recovery")
                os.fchmod(fd, op["target_mode"])
                actual_mode = stat.S_IMODE(os.fstat(fd).st_mode)
                result = {"path": op["path"], "success": actual_mode == op["target_mode"], "observed_mode": actual_mode}
            except (OSError, ValueError) as exc:
                result = {"path": op["path"], "success": False, "error": str(exc)}
            results.append(result)
            with ledger.transaction():
                ledger.event("recovery_operation", op["path"], op["object_id"], op["expected"], result, source="recovery", plan_id=plan_id)
            if not result["success"]:
                break
        with ledger.transaction():
            ledger.db.execute("UPDATE plans SET status=? WHERE id=?", ("applied" if len(results) == len(descriptors) and all(r["success"] for r in results) else "partial", plan_id))
        ledger.reconcile(p["root"], "After recovery " + plan_id)
        return {"plan_id": plan_id, "results": results, "rollback_snapshot": rollback}
    finally:
        for _, fd in descriptors:
            os.close(fd)
