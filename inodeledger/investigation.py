"""Derived investigation views with explicit observation-based confidence."""
from datetime import datetime, timezone
import hashlib
import json

from .metadata import beneath, canonical


def state_at(ledger, root, at):
    stamp = datetime.fromisoformat(at.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("Timestamp must include a timezone, such as +00:00")
    at = stamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
    root = canonical(root)
    states, gaps = {}, []
    for row in ledger.db.execute("SELECT payload FROM events WHERE time<=? ORDER BY seq", (at,)):
        event = json.loads(row[0])
        path = event["path"]
        if event["kind"] == "coverage_gap" and (not path or beneath(path, root) or beneath(root, path)):
            gaps.append(event)
        if not path or not beneath(path, root):
            continue
        if event["kind"] == "observed_missing":
            states.pop(path, None)
        elif event["kind"] in ("baseline", "observed_new", "replacement", "permission_change", "ownership_change", "acl_change", "metadata_change"):
            states[path] = {"path": path, "metadata": event["after"], "last_observed": event["time"], "object_id": event["object_id"]}
    return {"root": root, "at": at, "coverage": "partial: last observed states, not continuous audit" if states else "unknown: no recorded states", "entries": list(states.values()), "coverage_gaps": gaps}


def incidents(ledger, threshold=100, window_seconds=60):
    if threshold < 1 or window_seconds < 1:
        raise ValueError("Threshold and window must be positive")
    events = [json.loads(r[0]) for r in ledger.db.execute("SELECT payload FROM events WHERE kind='permission_change' ORDER BY seq")]
    groups = {}
    roots = [r["path"] for r in ledger.roots()]
    for e in events:
        root = next((root for root in roots if beneath(e["path"], root)), e["path"])
        stamp = datetime.fromisoformat(e["time"])
        buckets = groups.setdefault(root, [])
        if not buckets or (stamp - datetime.fromisoformat(buckets[-1][0]["time"])).total_seconds() > window_seconds:
            buckets.append([])
        buckets[-1].append(e)
    result = []
    for root, buckets in groups.items():
        for batch in buckets:
            risky = [e for e in batch if e.get("severity") == "high"]
            if len(batch) < threshold and not risky:
                continue
            result.append({"id": hashlib.sha256(batch[0]["id"].encode()).hexdigest()[:16], "root": root,
                           "first_observed": batch[0]["time"], "last_observed": batch[-1]["time"],
                           "changes": len(batch), "affected_objects": len({e["object_id"] for e in batch}),
                           "high_risk_changes": len(risky), "event_ids": [e["id"] for e in batch],
                           "confidence": "Derived grouping by root and observation time; not proof of one command", "actor": None})
    return list(reversed(result))
