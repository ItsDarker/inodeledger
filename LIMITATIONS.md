# Current boundaries

This release is a reduced-coverage development application, not production audit software.

- No Linux Audit, fanotify, inotify, eBPF, login/session, or process attribution.
- Polling misses transient/intermediate changes and cannot prove exact event times.
- Permission recovery is implemented for Linux but not validated on the development
  Windows host. Ownership, ACL, capability, or SELinux restoration is not implemented.
  Application is capped at 256 unique objects per plan to bound pinned descriptors.
- POSIX mode bits shown on Windows do not describe Windows ACLs. No NTFS ACL collection.
- Scans reject known symlink roots and record symlink children, but path-based collection
  is not hardened against hostile concurrent directory replacement. Do not run as root
  on adversarial trees. Descriptor-safe traversal for the collector remains future work.
- Device/inode identities do not reliably identify generations on all filesystems.
  Rename matches are candidates. Same-path inode reuse without observable birth time
  may be indistinguishable; recovery cannot claim absolute identity guarantees.
- No mount-boundary policy; scans include mounted subdirectories. NFS, overlayfs,
  network drives, pseudo-filesystems, and container namespaces are not validated.
- Access times may change due to inspection and are not used as change triggers.
  Changed mtime/size does not prove content change. No historical content versions.
- Encoding support is UTF BOMs and valid UTF-8/ASCII; legacy encodings are unknown.
  Signature detection is limited, not a libmagic replacement.
- No YARA-X integration, threat-indicator lists, scanner sandbox, or memory isolation.
  ClamAV adapter is tested with a simulated subprocess; a real engine is unavailable.
- No drag/drop, SSH/remote hosts, Tauri interface, saved filters, alert delivery,
  advanced ACL visualization, HTML/CSV reports, local-time display, or installers.
- Incident thresholds are command parameters, not a persistent policy engine.
- Desktop is manual-refresh; the background agent does not stream events to it.
- Current GUI table limits are 500 paths / 200 events; CLI supports offsets for paths.
- Scans cap at 250,000 entries; full scan transactions serialize writers and full export
  is memory-intensive. Millions-of-record performance is not validated.
- No retention, log pruning, storage quota, backup orchestration, or schema upgrades yet.
- Local hash chains cannot detect rewritten entire chains or deleted tails without an
  external trusted checkpoint. Exported files themselves are not verified by the command.
- Linux VM/container tests and the systemd example have not run on this Windows host.

Future work should prioritize descriptor-safe collection, Linux integration validation,
audit attribution, durable incremental exports, then scale and richer desktop workflows.
