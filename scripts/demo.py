"""Create real, isolated demo evidence and leave it available for UI exploration."""
import json
import os
from pathlib import Path
import tempfile

from inodeledger.store import Ledger
from inodeledger.recovery import plan


def main():
    base = Path(__file__).resolve().parents[1] / ".demo"
    base.mkdir(exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="session-", dir=base))
    root = workspace / "production"
    (root / "config").mkdir(parents=True)
    (root / "scripts").mkdir()
    config = root / "config" / "settings.yaml"
    config.write_text("environment: staging\nworkers: 2\n", encoding="utf-8")
    script = root / "scripts" / "deploy.sh"
    script.write_text("#!/bin/sh\nprintf 'demo only\\n'\n", encoding="utf-8")
    if os.name == "posix":
        config.chmod(0o640)
    ledger = Ledger(workspace / "ledger")
    first = ledger.add_root(root)
    if os.name == "posix":
        config.chmod(0o666)
    else:
        config.write_text("environment: staging\nworkers: 4\n# observed update\n", encoding="utf-8")
    script.rename(script.with_name("deploy-v2.sh"))
    second = ledger.reconcile(root, "After deployment")
    preview = plan(ledger, first["snapshot_id"])
    exports = ledger.materialize()
    ledger.close()
    reopened = Ledger(workspace / "ledger")
    try:
        assert reopened.verify()["valid"]
        assert len(reopened.events(path=config)) == 2
        print(json.dumps({"store": str(reopened.home), "root": str(root), "baseline": first,
                          "after": second, "recovery_plan": preview["id"], "exports": exports,
                          "integrity": reopened.verify(), "persistence_verified": True}, indent=2))
    finally:
        reopened.close()


if __name__ == "__main__":
    main()
