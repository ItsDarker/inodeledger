# Security model

Run the desktop, CLI, and agent as a normal user. Use a dedicated private ledger
directory outside monitored roots. New ledger directories request mode 0700 on POSIX;
Windows access control follows the parent directory's ACLs. Existing directories are
not silently re-permissioned. Protect database backups and exports as sensitive metadata.

No telemetry, cloud uploads, public network listeners, or mandatory online service.
File contents are read only for explicitly requested analysis, never executed or retained.
Filenames passed to ClamAV are argument-array elements after `--`; no shell is involved.
ClamAV has a 30-second timeout and 64 MiB scan limits, but is not OS-sandboxed.

Known symlink/junction roots are refused. The store rejects known symlinks at database
and export locations. These checks do not replace exclusive access to the ledger
directory; an attacker who can replace its ancestors can compromise its integrity.

Recovery is unavailable in the Windows UI/runtime. Linux CLI application requires
`--confirm` and refuses stale plans, blocked operations, and security xattrs it cannot
safely restore. It never invents default modes or applies recursive chmod. A partial
failure is retained; consult the plan and event ledger. Perform recovery with writers
stopped in a disposable environment until Linux integration has been independently verified.

Local privileged users can rewrite the database, exports, and checkpoints. Hash-chain
validation is tamper evidence under a trusted storage boundary, not tamper prevention.
It does not prove that no events were missed or deleted from the end of the chain.
