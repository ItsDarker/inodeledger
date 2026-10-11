# Testing

## Setup

Create a Python 3.12+ virtual environment, activate it, and install the development
package and pinned test dependencies:

```sh
python -m venv .venv
python -m pip install -e . -r requirements-test-lock.txt
python -m pytest -q
```

Activate with `source .venv/bin/activate` on Linux or
`.\.venv\Scripts\Activate.ps1` in PowerShell before the install step. Alternatively,
invoke `.venv/bin/python` or `.\.venv\Scripts\python.exe` directly.

`requirements-test.txt` declares the test tools; `requirements-test-lock.txt` pins
the tools and their dependencies for reproducible installations.

## Coverage

Tests use disposable directories and cover:

- Baselines, metadata changes, deletion, replacement, and database persistence.
- Snapshot comparison and historical state reconstruction.
- Hard-link identities and explicitly uncertain rename candidates.
- Coverage gaps without fabricated deletion events.
- Hash-chain tampering and repeatable mirrored exports.
- Bounded file analysis, encodings, signatures, and offline scanner behavior.
- Recovery confirmation and platform restrictions.
- Agent startup/shutdown, duplicate-agent exclusion, and CLI subprocesses.
- Native desktop construction and data loading when Tk and a display are available.
- Linux mode history and recovery when running on Linux.

The most recent Windows verification on October 11, 2026 reported **23 passed,
2 skipped**. Linux permission recovery and symlink creation requiring unavailable
Windows privileges were skipped. ClamAV tests simulate the external subprocess;
they do not validate a real scanner installation. No Linux Audit, systemd, or
privileged ACL validation is claimed.

## Demonstration

```sh
python scripts/demo.py
```

The script creates an isolated directory under `.demo/`, captures changes and
snapshots, generates audit exports, and reopens the database to check persistence.
It leaves the demo data available for desktop exploration. Generated data is
excluded from version control.

## Linux container harness

```sh
docker build -f tests/linux/Dockerfile -t inodeledger-tests .
docker run --rm inodeledger-tests
```

The headless container skips desktop tests and runs Linux filesystem tests against
disposable paths. This harness has not yet been executed on a Linux host. Passing
portable tests does not establish production readiness or complete audit coverage.
