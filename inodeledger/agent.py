"""Independent reconciliation service, with recorded startup/shutdown coverage gaps."""
import argparse
from contextlib import contextmanager
import os
import signal
import threading

from .metadata import reject_links
from .store import Ledger, now


@contextmanager
def agent_lock(home):
    path = home / "agent.lock"
    reject_links(path)
    handle = open(path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            handle.write(b"0")
            handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        handle.close()


def run(home=None, interval=10, stop=None):
    stop = stop or threading.Event()
    ledger = Ledger(home)
    try:
        with agent_lock(ledger.home):
            _loop(ledger, interval, stop)
    finally:
        ledger.close()


def _loop(ledger, interval, stop):
    with ledger.transaction():
        ledger.db.execute("INSERT OR REPLACE INTO settings VALUES('agent_stop','0')")
        ledger.db.execute("INSERT OR REPLACE INTO settings VALUES('agent_pid',?)", (str(os.getpid()),))
        ledger.event("coverage_gap", source="agent", reason="Agent started; activity since last observation is not fully captured")
    try:
        while not stop.is_set():
            with ledger.transaction():
                ledger.db.execute("INSERT OR REPLACE INTO settings VALUES('agent_heartbeat',?)", (now(),))
            request = ledger.db.execute("SELECT value FROM settings WHERE key='agent_stop'").fetchone()
            if request and request[0] == "1":
                break
            dirty = False
            for root in ledger.roots():
                if not root["enabled"] or stop.is_set():
                    continue
                try:
                    result = ledger.reconcile(root["path"])
                    dirty = dirty or bool(result["changes"] or result["errors"])
                except (OSError, ValueError) as exc:
                    with ledger.transaction():
                        ledger.event("coverage_gap", root["path"], source="agent", error=str(exc))
            if dirty:
                try:
                    ledger.materialize()
                except (OSError, ValueError) as exc:
                    with ledger.transaction():
                        ledger.event("export_error", source="agent", error=str(exc))
            stop.wait(max(1, interval))
    finally:
        with ledger.transaction():
            ledger.event("coverage_gap", source="agent", reason="Agent stopped; continuous monitoring unavailable")
            ledger.db.execute("DELETE FROM settings WHERE key IN ('agent_pid','agent_heartbeat')")


def main():
    p = argparse.ArgumentParser(description="InodeLedger reconciliation agent")
    p.add_argument("--home")
    p.add_argument("--interval", type=float, default=10)
    args = p.parse_args()
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    run(args.home, args.interval, stop)


if __name__ == "__main__":
    main()
