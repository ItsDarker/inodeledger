import json
import os
from pathlib import Path
import stat
import sys
import threading

import pytest

from inodeledger.agent import run
from inodeledger.metadata import canonical, native_path
from inodeledger.recovery import apply, plan
from inodeledger.security import analyze
from inodeledger.store import Ledger


@pytest.fixture
def env(tmp_path):
    root = tmp_path / "watched"
    root.mkdir()
    ledger = Ledger(tmp_path / "ledger")
    yield ledger, root
    ledger.close()


def test_baseline_changes_deletion_and_restart(env):
    ledger, root = env
    file = root / "settings.txt"
    file.write_text("initial", encoding="utf-8")
    first = ledger.add_root(root)
    assert first["observed"] == 2
    assert ledger.events(path=file)[0]["kind"] == "baseline"
    file.write_text("changed configuration", encoding="utf-8")
    ledger.reconcile(root)
    event = ledger.events(path=file)[0]
    assert event["kind"] == "metadata_change"
    assert event["before"]["size"] == 7
    assert event["after"]["size"] == 21
    assert event["actor"] is None
    file.unlink()
    ledger.reconcile(root)
    assert ledger.events(path=file)[0]["kind"] == "observed_missing"
    other = Ledger(ledger.home)
    try:
        assert len(other.events(path=file)) == 3
        assert other.verify()["valid"]
    finally:
        other.close()


def test_snapshot_diff_and_no_prior_history(env):
    ledger, root = env
    file = root / "new.txt"
    first = ledger.add_root(root)["snapshot_id"]
    assert ledger.events(path=file) == []
    file.write_text("new", encoding="utf-8")
    second = ledger.reconcile(root, "Release")["snapshot_id"]
    diff = ledger.diff(first, second)
    assert any(d["path"] == canonical(file) and d["before"] is None for d in diff)
    assert ledger.snapshots()[0]["name"] == "Release"


def test_hash_chain_detects_tampering(env):
    ledger, root = env
    ledger.add_root(root)
    assert ledger.verify()["valid"]
    ledger.db.execute("UPDATE events SET payload='{}' WHERE seq=1")
    ledger.db.commit()
    assert not ledger.verify()["valid"]
    with pytest.raises(ValueError, match="Integrity"):
        ledger.materialize()


def test_export_is_repeatable_and_mirrors(env):
    ledger, root = env
    (root / "settings.json").write_text("{}")
    ledger.add_root(root)
    ledger.materialize()
    journals = list((ledger.home / "events").glob("*.jsonl"))
    first = journals[0].read_bytes()
    ledger.materialize()
    assert journals[0].read_bytes() == first
    records = [json.loads(line) for line in first.splitlines()]
    assert len(records) == 2
    assert len(list(native_path(ledger.home / "hosts").rglob("_history.txt"))) == 2


def test_storage_recursion_and_overlapping_roots_refused(env):
    ledger, root = env
    with pytest.raises(ValueError, match="separate"):
        ledger.add_root(root.parent)
    ledger.add_root(root)
    child = root / "sub"
    child.mkdir()
    with pytest.raises(ValueError, match="Overlapping"):
        ledger.add_root(child)


def test_atomic_replacement_is_not_old_object(env):
    ledger, root = env
    file = root / "file.txt"
    file.write_text("before")
    ledger.add_root(root)
    old = ledger.events(path=file)[0]["object_id"]
    replacement = root / "temporary"
    replacement.write_text("after")
    os.replace(replacement, file)
    ledger.reconcile(root)
    event = ledger.events(path=file)[0]
    assert event["kind"] == "replacement"
    assert event["object_id"] != old


def test_rename_is_candidate_not_proven(env):
    ledger, root = env
    before, after = root / "before", root / "after"
    before.write_text("data")
    ledger.add_root(root)
    before.rename(after)
    ledger.reconcile(root)
    e = ledger.events(path=after)[0]
    assert e["kind"] == "observed_new"
    assert canonical(before) in e["possible_previous_paths"]
    assert ledger.events(path=before)[0]["kind"] == "observed_missing"


def test_hardlinks_share_identity(env):
    ledger, root = env
    a, b = root / "a", root / "b"
    a.write_text("data")
    try:
        os.link(a, b)
    except OSError:
        pytest.skip("Hard links unavailable")
    ledger.add_root(root)
    assert ledger.events(path=a)[0]["object_id"] == ledger.events(path=b)[0]["object_id"]


def test_failed_subtree_does_not_invent_deletions(env, monkeypatch):
    ledger, root = env
    file = root / "protected"
    file.write_text("evidence")
    ledger.add_root(root)
    from inodeledger.metadata import capture
    monkeypatch.setattr("inodeledger.store.collect", lambda _: ({canonical(root): capture(root)}, [{"path": canonical(file), "error": "permission denied"}]))
    result = ledger.reconcile(root, "Partial")
    assert result["errors"]
    assert ledger.events(path=file)[0]["kind"] == "baseline"
    assert ledger.snapshots()[0]["complete"] == 0
    assert ledger.events(kind="coverage_gap")


def test_symlink_not_followed(env):
    ledger, root = env
    target = root.parent / "outside.txt"
    target.write_text("secret")
    link = root / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks need Windows developer mode or privilege")
    ledger.add_root(root)
    assert ledger.events(path=link)[0]["after"]["kind"] == "symlink"
    with pytest.raises(ValueError, match="Symlink"):
        analyze(link)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32"])
def test_encoding_detection(env, encoding):
    _, root = env
    file = root / "text.txt"
    file.write_bytes("Hello λ\r\nWorld\r\n".encode(encoding))
    result = analyze(file)
    assert result["encoding"] == encoding
    assert result["line_endings"] == "CRLF"
    assert len(result["sha256"]) == 64
    assert not result["content_retained"]


def test_analysis_bound_and_signature(env):
    _, root = env
    file = root / "image.txt"
    file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
    assert analyze(file)["extension_mismatch"]
    with pytest.raises(ValueError, match="limit"):
        analyze(file, max_bytes=4)


def test_agent_reconciles_and_stops(env):
    ledger, root = env
    ledger.add_root(root)
    (root / "agent.txt").write_text("data")
    stop = threading.Event()
    thread = threading.Thread(target=run, args=(ledger.home, 1, stop))
    thread.start()
    import time
    deadline = time.monotonic() + 5
    try:
        while not ledger.events(path=root / "agent.txt") and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ledger.events(path=root / "agent.txt")
    finally:
        stop.set()
        thread.join(5)
    assert not thread.is_alive()
    assert ledger.status()["gaps"] >= 2


def test_recovery_requires_confirmation(env):
    ledger, root = env
    sid = ledger.add_root(root)["snapshot_id"]
    p = plan(ledger, sid)
    assert p["dry_run"]
    with pytest.raises(ValueError, match="confirm"):
        apply(ledger, p["id"])


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Real Linux permission semantics required")
def test_linux_permission_history_recovery(env):
    ledger, root = env
    file = root / "config"
    file.write_text("unchanged")
    file.chmod(0o640)
    sid = ledger.add_root(root)["snapshot_id"]
    file.chmod(0o666)
    ledger.reconcile(root)
    event = ledger.events(path=file)[0]
    assert event["before"]["octal"] == "0640"
    assert event["after"]["octal"] == "0666"
    p = plan(ledger, sid)
    assert p["operations"][0]["status"] == "ready"
    result = apply(ledger, p["id"], confirm=True)
    assert result["results"][0]["success"]
    assert stat.S_IMODE(file.stat().st_mode) == 0o640


def test_desktop_constructs_and_loads(env):
    tk = pytest.importorskip("tkinter")
    from inodeledger.gui import App
    ledger, root = env
    (root / "desktop.txt").write_text("hello")
    ledger.add_root(root)
    try:
        window = tk.Tk()
    except tk.TclError:
        pytest.skip("Display unavailable")
    window.withdraw()
    app = App(window, ledger.home)
    import time
    deadline = time.monotonic() + 5
    while app.busy and time.monotonic() < deadline:
        window.update()
        time.sleep(0.02)
    try:
        assert not app.busy
        assert len(app.files_tree.get_children()) == 2
        assert len(app.events_tree.get_children()) == 2
    finally:
        app.closed = True
        app.executor.shutdown(wait=True)
        window.destroy()


def test_historical_state_reconstruction(env):
    from inodeledger.investigation import state_at
    ledger, root = env
    file = root / "state.txt"
    file.write_text("old")
    ledger.add_root(root)
    stamp = ledger.events(path=file)[0]["time"]
    file.write_text("new and longer")
    ledger.reconcile(root)
    state = state_at(ledger, root, stamp)
    assert next(e for e in state["entries"] if e["path"] == canonical(file))["metadata"]["size"] == 3
    assert state_at(ledger, root, "2000-01-01T00:00:00Z")["entries"] == []
    with pytest.raises(ValueError, match="timezone"):
        state_at(ledger, root, "2026-10-11T12:00:00")


def test_incident_grouping_is_explicitly_derived(env):
    from inodeledger.investigation import incidents
    ledger, root = env
    ledger.add_root(root)
    with ledger.transaction():
        for index in range(101):
            ledger.event("permission_change", canonical(root / str(index)), str(index), {"mode": 0o640}, {"mode": 0o666}, severity="high")
    result = incidents(ledger)
    assert len(result) == 1
    assert result[0]["affected_objects"] == 101
    assert result[0]["actor"] is None
    assert "not proof" in result[0]["confidence"]


def test_clamav_unavailable_is_not_clean(env, monkeypatch):
    from inodeledger.security import scan
    _, root = env
    file = root / "sample"
    file.write_text("not executed")
    monkeypatch.setattr("inodeledger.security.shutil.which", lambda _: None)
    assert scan(file)["status"] == "scan_unavailable"


def test_scanner_arguments_never_use_shell(env, monkeypatch):
    from inodeledger.security import scan
    import subprocess
    _, root = env
    file = root / "suspicious file.txt"
    file.write_text("sample")
    calls = []
    monkeypatch.setattr("inodeledger.security.shutil.which", lambda _: "clamscan")
    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0 if "--version" in args else 1, "Test scanner" if "--version" in args else "sample: Test.Signature FOUND", "")
    monkeypatch.setattr("inodeledger.security.subprocess.run", fake_run)
    result = scan(file)
    assert result["status"] == "detected_threat"
    assert calls[-1][0][-2:] == ["--", canonical(file)]
    assert not calls[-1][1].get("shell")


def test_cli_separate_processes_persist(env):
    import subprocess
    ledger, root = env
    file = root / "cli.txt"
    file.write_text("actual data")
    command = [sys.executable, "-m", "inodeledger", "--home", str(ledger.home)]
    added = subprocess.run(command + ["watch", "add", str(root)], capture_output=True, text=True)
    assert added.returncode == 0, added.stderr
    history = subprocess.run(command + ["history", str(file)], capture_output=True, text=True)
    assert history.returncode == 0, history.stderr
    assert json.loads(history.stdout)[0]["after"]["size"] == 11
    integrity = subprocess.run(command + ["verify-integrity"], capture_output=True, text=True)
    assert integrity.returncode == 0
    assert json.loads(integrity.stdout)["valid"]


def test_agent_duplicate_lock_is_refused(env):
    from inodeledger.agent import agent_lock
    ledger, _ = env
    with agent_lock(ledger.home):
        with pytest.raises(OSError):
            with agent_lock(ledger.home):
                pass


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="Linux supports descriptor-based application")
def test_windows_recovery_application_refused(env):
    ledger, root = env
    sid = ledger.add_root(root)["snapshot_id"]
    p = plan(ledger, sid)
    with pytest.raises(ValueError, match="requires Linux"):
        apply(ledger, p["id"], confirm=True)
