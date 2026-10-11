"""Bounded metadata collection. Symlinks are recorded, never traversed."""
import base64
import os
from pathlib import Path
import stat


def canonical(path):
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def native_path(path):
    """Allow generated mirror paths beyond Windows' legacy MAX_PATH limit."""
    value = os.path.abspath(os.fspath(path))
    if os.name == "nt" and not value.startswith("\\\\?\\"):
        value = "\\\\?\\UNC\\" + value[2:] if value.startswith("\\\\") else "\\\\?\\" + value
    return Path(value)


def beneath(path, root):
    try:
        return os.path.commonpath([canonical(path), canonical(root)]) == canonical(root)
    except ValueError:
        return False


def reject_links(path):
    p = Path(canonical(path))
    for part in [*reversed(p.parents), p]:
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError(f"Symlink/junction traversal refused: {part}")
    return p


def capture(path):
    s = os.lstat(path)
    kind = "symlink" if stat.S_ISLNK(s.st_mode) else "directory" if stat.S_ISDIR(s.st_mode) else "file" if stat.S_ISREG(s.st_mode) else "special"
    attrs, attr_error = {}, None
    if hasattr(os, "listxattr"):
        try:
            for key in os.listxattr(path, follow_symlinks=False):
                # ACL, capability, and security contexts are kept as raw evidence.
                if key.startswith(("system.posix_acl", "security.")):
                    attrs[key] = base64.b64encode(os.getxattr(path, key, follow_symlinks=False)).decode()
        except OSError as exc:
            attr_error = str(exc)
    else:
        attr_error = "Extended attributes unavailable on this platform"
    return {"device": s.st_dev, "inode": s.st_ino, "kind": kind,
            "mode": stat.S_IMODE(s.st_mode), "octal": f"{stat.S_IMODE(s.st_mode):04o}",
            "symbolic": stat.filemode(s.st_mode), "uid": s.st_uid, "gid": s.st_gid,
            "size": s.st_size, "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns,
            "atime_ns": s.st_atime_ns, "birthtime_ns": getattr(s, "st_birthtime_ns", None),
            "links": s.st_nlink, "xattrs": attrs, "xattr_error": attr_error,
            "target": os.readlink(path) if kind == "symlink" else None}


def collect(root, max_entries=250000):
    reject_links(root)
    found, errors, pending = {}, [], [canonical(root)]
    while pending:
        path = pending.pop()
        try:
            if len(found) >= max_entries:
                raise ValueError(f"Scan limit of {max_entries} entries exceeded")
            m = capture(path)
            found[path] = m
            if m["kind"] == "directory":
                with os.scandir(path) as children:
                    for child in children:
                        if getattr(child, "is_junction", lambda: False)():
                            errors.append({"path": child.path, "error": "Junction excluded"})
                        else:
                            pending.append(child.path)
        except OSError as exc:
            errors.append({"path": path, "error": str(exc)})
    return found, errors


def changed(before, after):
    fields = ("mode", "uid", "gid", "size", "mtime_ns", "ctime_ns", "xattrs", "target", "links")
    return [key for key in fields if before.get(key) != after.get(key)]
