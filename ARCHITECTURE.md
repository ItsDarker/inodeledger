# Architecture

`metadata.py` captures lstat evidence and performs bounded recursive reconciliation.
It records symlinks as objects, skips Windows junctions, and collects raw POSIX ACL /
security xattrs where the OS exposes them. No file contents are retained in baselines.

`store.py` serializes each scan under a SQLite immediate transaction. WAL supports
concurrent readers. Current paths, durable objects, version events, snapshot entries,
and recovery plans have separate tables. Event payloads include before/after metadata,
stable UUIDs, a host UUID, source, observation timestamp, and explicitly unknown actors.
Each event hash covers its canonical JSON and the preceding hash. Version 1 bootstraps
the schema; no upgrade migrations exist yet.

SQLite commits are the authoritative journal. Export generates daily JSONL and
human-readable per-path records from committed events using fsync + atomic replacement.
Export is repeatable after a crash and does not duplicate entries. It is not an
independently appended external journal. The escaped hierarchy includes component
hashes to avoid Windows case and special-name collisions. Windows extended paths
support deep mirrored trees. Full export currently uses memory proportional to history.

`agent.py` is an independent process. An OS file lock prevents duplicate agents for
one store; a persistent heartbeat and stop request support desktop control. Startup,
shutdown, and failed scans record coverage gaps. Changed scans regenerate reports.
The OS process may be supervised by the sample systemd user unit.

`security.py` detects a small set of signatures, BOM/UTF encodings, line endings,
entropy, and SHA-256 without executing content. ClamAV is a separately invoked,
time-bounded optional local engine. Neither module uploads files.

`investigation.py` reconstructs last-observed states and derives permission clusters
by root and observation time. Grouping never establishes common actor attribution.

`recovery.py` builds stored, mode-only plans from explicit snapshot IDs. Application
requires Linux and confirmation. It uses no-follow directory-relative opens and
fchmod on retained descriptors, checks expected identity/state, persists intent, and
records every attempted change. It is not atomic across a tree or against concurrent
external writers. Crashes may leave a plan marked `applying`; review its events and
live state, then create a new plan. Do not blindly retry the old plan.

`cli.py` exposes JSON commands. `gui.py` is an unprivileged Tk desktop using a single
worker thread and a UI result queue; filesystem and DB work do not block the UI thread.
The desktop and daemon have independent lifetimes. There is no HTTP listener or remote API.
