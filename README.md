# InodeLedger

**Every file has a history. Every change has a reason.**

InodeLedger is an offline filesystem metadata history and investigation tool by
[ItsDarker](https://github.com/ItsDarker). It records directory baselines, tracks
observed changes in SQLite, and provides a desktop application and command-line
interface for investigating files, comparing snapshots, and reviewing permission
recovery plans.

**Status:** early development, version 0.1.0. Monitoring uses periodic reconciliation.
It does not provide continuous kernel auditing or identify the user or process
responsible for a change. Review the [limitations](LIMITATIONS.md) before deployment.

## Features

| Area | Capabilities |
| --- | --- |
| Monitoring | Directory baselines, manual reconciliation, independent background agent, coverage-gap records |
| History | Before/after metadata, deleted-file history, replacement detection, hard-link identities, possible rename matches |
| Investigation | Searchable paths, event history, last-observed historical state, permission-change clusters |
| Snapshots | Named captures, comparisons, explicit historical permission targets |
| Recovery | Stored mode-restoration previews; guarded, Linux-only application through the CLI |
| Analysis | SHA-256, selected file signatures, UTF encodings, line endings, entropy, optional local ClamAV scanning |
| Audit records | Daily JSONL exports, mirrored per-path reports, event hash-chain verification |
| Interfaces | Native Tk desktop and JSON command-line output |

The application has no telemetry, cloud uploads, public network listener, or
third-party Python runtime dependencies. File contents are not retained.

## Requirements

- Python **3.12 or newer**, with virtual-environment support.
- Linux or Windows. Linux-specific permission behavior is not available on Windows.
- Tk and a graphical session for the desktop. The CLI and agent work without Tk.
- Optional: ClamAV's `clamscan` executable and a local signature database.
- Optional: Docker on a Linux host for the container test harness.

On Ubuntu/Debian, Tk and virtual-environment support are available through
`python3-tk` and `python3-venv`. Ensure the selected interpreter is Python 3.12+.

## Installation

Clone the repository:

```sh
git clone https://github.com/ItsDarker/inodeledger.git
cd inodeledger
```

### Windows

Run in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m inodeledger gui
```

After installation, you can also double-click `Launch InodeLedger.cmd`.
Activation is optional; these commands use the environment directly.

### Linux

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m inodeledger gui
```

For CLI-only use, omit the last command. Activate the environment with
`source .venv/bin/activate`, or invoke `.venv/bin/inodeledger` directly.

## First investigation

1. Open **Explorer** and select **Monitor folder** to capture a baseline.
2. Modify a file in that folder, then select **Reconcile now**.
3. Select the file to review its last recorded and newly observed metadata.
4. Open **Activity** to inspect changes, including files that are now missing.
5. Use **Snapshots & recovery** to capture named snapshots, compare the latest two
   snapshots of a root, or preview recovery from a selected snapshot.
6. Open **Health & evidence** to verify the event chain or export audit reports.

For background monitoring, choose **Start background monitor** under **Health &
evidence**. It polls every ten seconds and continues after the desktop closes.
Use **Stop monitor** to request shutdown. Refresh the desktop to see new records.

No directories are monitored until explicitly added. A file without recorded
history has an unknown prior state.

## Command-line usage

These examples assume the virtual environment is activated. Query output is JSON.
`python -m inodeledger` can be used instead of `inodeledger`.

### Monitoring and health

```sh
inodeledger init
inodeledger watch add /srv/example
inodeledger watch list
inodeledger reconcile /srv/example
inodeledger status
inodeledger health
inodeledger watch remove /srv/example
```

Removing a root stops monitoring; its history is retained. Run the agent in a
separate terminal or under a service manager:

```sh
inodeledger-agent --interval 10
```

Request shutdown from another terminal with `inodeledger stop-agent`. An OS lock
prevents multiple agents from using one store concurrently. Status output includes
the latest recorded agent heartbeat. A sample systemd user unit is included in
[`packaging/systemd/`](packaging/systemd/inodeledger-agent.service); edit its
executable path before installing it.

### File history and analysis

```sh
inodeledger inspect /srv/example/config.yaml
inodeledger history /srv/example/config.yaml
inodeledger tree --search config --limit 100 --offset 0
inodeledger events --type permission_change --limit 100
inodeledger encoding /srv/example/config.yaml
inodeledger scan /srv/example/config.yaml
```

Analysis reads regular files up to 64 MiB. Scanning reports unavailable or incomplete
engines explicitly. No detection is not proof that a file is safe.

### Snapshots and historical state

```sh
inodeledger snapshot create /srv/example --name before-deploy
inodeledger snapshot list
inodeledger snapshot diff SNAPSHOT_A SNAPSHOT_B
inodeledger state /srv/example --at "2026-10-11T12:00:00+00:00"
inodeledger incidents --threshold 100 --window 60
```

Replace uppercase identifiers with returned IDs. Historical state means the last
observation recorded by the requested time. Incident groups are derived from root
paths and observation times; they do not prove a common command or actor.

### Permission recovery

Start with an explicitly selected historical snapshot:

```sh
inodeledger recovery plan SNAPSHOT_ID
inodeledger recovery preview PLAN_ID
```

Plans are previews by default. On Linux, application requires explicit confirmation:

```sh
inodeledger recovery apply PLAN_ID --confirm
```

Recovery is experimental and has not yet been validated on a Linux host. Evaluate
it in disposable directories. Application restores traditional mode bits only and
refuses blocked targets, stale state, symlink traversal, and unsupported extended
security metadata. A plan is limited to 256 unique objects. Ownership and ACL
restoration are not supported.

Recovery records intent, pins target descriptors, stores a pre-recovery snapshot,
and records attempted operations. It is not atomic across a tree; stop concurrent
writers first. To undo a restoration, review a new plan targeting the pre-recovery
snapshot. Rollback is never automatic. The desktop exposes previews only.

### Audit exports

```sh
inodeledger export
inodeledger verify-integrity
```

SQLite is the authoritative record. Export regenerates daily JSONL journals and
per-path reports using escaped directory components. The agent also regenerates
exports after observing changes. Verification checks stored event hashes, not every
database table or exported file.

Use `inodeledger --help` or `inodeledger COMMAND --help` for command options.

## Data storage

| Platform | Default directory |
| --- | --- |
| Windows | `%USERPROFILE%\.inodeledger` |
| Linux | `~/.inodeledger` |

Set `INODELEDGER_HOME`, or pass `--home PATH` **before** the command:

```sh
inodeledger --home /path/to/ledger status
```

The store must be outside monitored roots. Use the same directory for the desktop,
CLI, and agent to access the same history. Alongside agent control files, it contains:

```text
ledger/
├── history.sqlite
├── events/
│   └── YYYY-MM-DD.jsonl
└── hosts/
    └── HOST_ID/mirror/
        └── escaped/path/components/
            ├── _history.audit.jsonl
            └── _history.txt
```

Protect the store as sensitive metadata. Stop all application processes before a
filesystem-level backup of the complete directory, including any SQLite WAL files.
Retention and automatic backup management are not implemented.

## Evidence and security boundaries

- Before values are the **last recorded state**, not guaranteed syscall pre-state.
- Timestamps are UTC observation times. Actors and processes remain unknown.
- Polling can miss short-lived files and intermediate changes.
- Metadata changes do not by themselves prove content changes.
- Rename matches are candidates. Inode identity cannot exclude every reuse case.
- Windows mode bits do not represent NTFS ACLs.
- Local hash chains cannot rule out privileged rewriting or tail deletion.
- Run as a normal user. Collection is not hardened for privileged monitoring of
  adversarial directory trees.

See [Security](SECURITY.md) and [Limitations](LIMITATIONS.md) for the full boundaries.

## Development and testing

In an activated virtual environment:

```sh
python -m pip install -e . -r requirements-test-lock.txt
python -m pytest -q
python scripts/demo.py
```

The demo creates an isolated `.demo/` directory, records real changes, exports
reports, and verifies reopened database persistence. Use its printed store path
with `inodeledger --home PATH gui` to explore the results.

The latest recorded Windows run passed **23 tests**, with **2 platform-dependent
skips**. Linux permission application and privileged symlink behavior remain
unverified. ClamAV adapter tests use a simulated subprocess.

For the Linux container harness:

```sh
docker build -f tests/linux/Dockerfile -t inodeledger-tests .
docker run --rm inodeledger-tests
```

The harness is provided but has not yet run on a Linux host. See
[Testing](TESTING.md) for coverage and prerequisites.

## Repository layout

```text
inodeledger/          Application, CLI, desktop, agent, and storage modules
packaging/systemd/   Example systemd user service
scripts/demo.py      Isolated filesystem-history demonstration
tests/               Automated tests and Linux container harness
pyproject.toml       Package metadata and command entry points
```

Design details are documented in [Architecture](ARCHITECTURE.md).

## Troubleshooting

| Issue | Action |
| --- | --- |
| Desktop does not open | Check Tk with `python -m tkinter`; launch from a terminal to see errors. |
| No new events | Reconcile or start the agent, then refresh. Check heartbeat and coverage gaps. |
| Root rejected | Choose an existing directory outside the store; overlapping roots and symlink/junction roots are refused. |
| Scanner unavailable | Install `clamscan` and its local database; ensure the executable is on `PATH`. |
| Recovery blocked | Review preview reasons and current state before creating a new plan. |
| Integrity failure | Preserve the store for investigation; do not treat subsequent exports as verified evidence. |

To uninstall, stop the monitor, close the desktop, and run
`python -m pip uninstall inodeledger` in the virtual environment. Ledger data is
retained and must be archived or removed separately.

## Ownership and license

Created and maintained by **[ItsDarker](https://github.com/ItsDarker)**.

Copyright © 2026 ItsDarker. Distributed under the [MIT License](LICENSE).
