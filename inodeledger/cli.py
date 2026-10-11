import argparse
import json
import os
import sqlite3
import sys

from .store import Ledger


def parser():
    p = argparse.ArgumentParser(prog="inodeledger", description="Filesystem history from recorded evidence. Use 'gui' for the desktop application.")
    p.add_argument("--home", help="Ledger data directory; default ~/.inodeledger")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("init", "status", "health", "verify-integrity", "export", "gui"):
        sub.add_parser(name)
    sub.add_parser("stop-agent")
    state = sub.add_parser("state")
    state.add_argument("path")
    state.add_argument("--at", required=True)
    incident = sub.add_parser("incidents")
    incident.add_argument("--threshold", type=int, default=100)
    incident.add_argument("--window", type=int, default=60)
    watch = sub.add_parser("watch").add_subparsers(dest="action", required=True)
    watch.add_parser("list")
    for name in ("add", "remove"):
        watch.add_parser(name).add_argument("path")
    sub.add_parser("reconcile").add_argument("path", nargs="?")
    for name in ("inspect", "history", "encoding", "scan"):
        sub.add_parser(name).add_argument("path")
    tree = sub.add_parser("tree")
    tree.add_argument("--search", default="")
    tree.add_argument("--limit", type=int, default=500)
    tree.add_argument("--offset", type=int, default=0)
    events = sub.add_parser("events")
    events.add_argument("--type", dest="kind")
    events.add_argument("--limit", type=int, default=200)
    snap = sub.add_parser("snapshot").add_subparsers(dest="action", required=True)
    snap.add_parser("list")
    create = snap.add_parser("create")
    create.add_argument("path")
    create.add_argument("--name", default="Manual snapshot")
    diff = snap.add_parser("diff")
    diff.add_argument("first")
    diff.add_argument("second")
    rec = sub.add_parser("recovery").add_subparsers(dest="action", required=True)
    rec.add_parser("plan").add_argument("snapshot_id")
    rec.add_parser("preview").add_argument("plan_id")
    apply = rec.add_parser("apply")
    apply.add_argument("plan_id")
    apply.add_argument("--confirm", action="store_true")
    agent = sub.add_parser("agent")
    agent.add_argument("--interval", type=float, default=10)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command == "gui":
        from .gui import main as gui
        gui(args.home)
        return
    if args.command == "agent":
        from .agent import run
        try:
            run(args.home, args.interval)
        except KeyboardInterrupt:
            pass
        return
    ledger = Ledger(args.home)
    try:
        c = args.command
        if c in ("init", "status", "health"):
            result = ledger.status()
        elif c == "watch":
            result = ledger.roots() if args.action == "list" else ledger.add_root(args.path) if args.action == "add" else ledger.remove_root(args.path)
        elif c == "stop-agent":
            result = ledger.stop_agent()
        elif c == "state":
            from .investigation import state_at
            result = state_at(ledger, args.path, args.at)
        elif c == "incidents":
            from .investigation import incidents
            result = incidents(ledger, args.threshold, args.window)
        elif c == "reconcile":
            result = ledger.reconcile(args.path) if args.path else [ledger.reconcile(r["path"]) for r in ledger.roots() if r["enabled"]]
        elif c == "tree":
            result = ledger.files(args.search, args.limit, args.offset)
        elif c in ("history", "events"):
            result = ledger.events(path=args.path) if c == "history" else ledger.events(kind=args.kind, limit=args.limit)
        elif c == "inspect":
            from .metadata import canonical, capture
            history = ledger.events(path=args.path)
            result = {"path": canonical(args.path), "current": capture(args.path), "history": history, "prior_state": "Recorded evidence available" if history else "Unknown: no historical record"}
        elif c in ("encoding", "scan"):
            from .security import analyze, scan
            result = analyze(args.path) if c == "encoding" else scan(args.path)
            with ledger.transaction():
                ledger.event("file_analysis" if c == "encoding" else "malware_scan", args.path, source="analysis", result=result)
        elif c == "snapshot":
            result = ledger.snapshots() if args.action == "list" else ledger.reconcile(args.path, args.name) if args.action == "create" else ledger.diff(args.first, args.second)
        elif c == "recovery":
            from .recovery import plan, preview, apply
            result = plan(ledger, args.snapshot_id) if args.action == "plan" else preview(ledger, args.plan_id) if args.action == "preview" else apply(ledger, args.plan_id, args.confirm)
        elif c == "export":
            result = ledger.materialize()
        else:
            result = ledger.verify()
        print(json.dumps(result, indent=2, ensure_ascii=True))
        if c == "verify-integrity" and not result["valid"]:
            raise SystemExit(1)
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    finally:
        ledger.close()
