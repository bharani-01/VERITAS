"""Admin host filesystem helpers — browse mounted disks safely."""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException

from app.core.config import FS_BLOCKED_NAMES, FS_DOWNLOAD_MAX_BYTES

# Virtual / ephemeral mounts — never expose as browsable roots.
_SKIP_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/snapd")
_SKIP_FSTYPES = frozenset(
    {
        "proc",
        "sysfs",
        "devtmpfs",
        "devpts",
        "tmpfs",
        "cgroup",
        "cgroup2",
        "securityfs",
        "pstore",
        "bpf",
        "tracefs",
        "debugfs",
        "hugetlbfs",
        "mqueue",
        "overlay",
        "squashfs",
        "nsfs",
        "autofs",
        "fusectl",
        "configfs",
        "rpc_pipefs",
        "binfmt_misc",
    }
)

# Absolute paths that must never be downloaded (even if listed).
_BLOCKED_ABSOLUTE = frozenset(
    {
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/passwd-",
        "/etc/shadow-",
        "/etc/sudoers",
    }
)


def _blocked_basenames() -> set[str]:
    raw = FS_BLOCKED_NAMES or ""
    names = {n.strip().lower() for n in raw.split(",") if n.strip()}
    # Always include high-risk defaults
    names.update(
        {
            ".env",
            ".env.local",
            ".env.production",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            "id_dsa",
            "shadow",
            "gshadow",
            "sudoers",
            "credentials.json",
            "serviceaccount.json",
        }
    )
    return names


def _is_blocked_download(path: Path) -> bool:
    resolved = str(path.resolve())
    if resolved in _BLOCKED_ABSOLUTE:
        return True
    name = path.name.lower()
    if name in _blocked_basenames():
        return True
    # Private key material
    if name.endswith(".pem") and "private" in name:
        return True
    if name.endswith((".key", ".p12", ".pfx")):
        return True
    # Common secret filenames
    if name.startswith(".env.") or name.endswith(".env"):
        return True
    return False


def _should_skip_mount(mountpoint: str, fstype: str | None, source: str | None) -> bool:
    mp = mountpoint or ""
    ft = (fstype or "").lower()
    if ft in _SKIP_FSTYPES:
        return True
    if any(mp == p or mp.startswith(p + "/") for p in _SKIP_PREFIXES):
        return True
    # Skip loop/snap bind noise
    if source and ("/snap/" in source or source.startswith("/dev/loop")):
        return True
    if mp.startswith("/snap"):
        return True
    return False


def _human_bytes(n: int | None) -> str | None:
    if n is None:
        return None
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _human_bytes(n: int | None) -> str | None:
    if n is None:
        return None
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _usage_for(mountpoint: str) -> dict:
    try:
        usage = shutil.disk_usage(mountpoint)
        total, used, free = usage.total, usage.used, usage.free
        percent = int(round(100.0 * used / total)) if total else 0
        return {
            "size_bytes": total,
            "used_bytes": used,
            "avail_bytes": free,
            "percent": percent,
            "size": _human_bytes(total),
            "used": _human_bytes(used),
            "avail": _human_bytes(free),
        }
    except OSError:
        return {
            "size_bytes": None,
            "used_bytes": None,
            "avail_bytes": None,
            "percent": None,
            "size": None,
            "used": None,
            "avail": None,
        }


def _list_mounts_findmnt() -> list[dict]:
    try:
        proc = subprocess.run(
            ["findmnt", "-J", "-o", "TARGET,SOURCE,FSTYPE,SIZE,USED,AVAIL,USE%,OPTIONS"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return []
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    filesystems = data.get("filesystems") or []
    out: list[dict] = []

    def walk(nodes: list) -> None:
        for node in nodes:
            if not isinstance(node, dict):
                continue
            target = node.get("target") or node.get("TARGET")
            source = node.get("source") or node.get("SOURCE")
            fstype = node.get("fstype") or node.get("FSTYPE")
            if target and not _should_skip_mount(str(target), fstype, source):
                usage = _usage_for(str(target))
                out.append(
                    {
                        "mountpoint": str(target),
                        "source": str(source or ""),
                        "fstype": str(fstype or ""),
                        **usage,
                    }
                )
            children = node.get("children") or []
            if children:
                walk(children)

    walk(filesystems if isinstance(filesystems, list) else [])
    return out


def _list_mounts_df() -> list[dict]:
    try:
        proc = subprocess.run(
            ["df", "-P", "-B1"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return []
    lines = (proc.stdout or "").splitlines()
    out: list[dict] = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        source, size_s, used_s, avail_s, pct_s, *rest = parts
        mountpoint = rest[-1] if rest else ""
        if not mountpoint or _should_skip_mount(mountpoint, None, source):
            continue
        try:
            total = int(size_s)
            used = int(used_s)
            free = int(avail_s)
            percent = int(pct_s.rstrip("%")) if pct_s else 0
        except ValueError:
            usage = _usage_for(mountpoint)
            out.append({"mountpoint": mountpoint, "source": source, "fstype": "", **usage})
            continue
        out.append(
            {
                "mountpoint": mountpoint,
                "source": source,
                "fstype": "",
                "size_bytes": total,
                "used_bytes": used,
                "avail_bytes": free,
                "percent": percent,
                "size": _human_bytes(total),
                "used": _human_bytes(used),
                "avail": _human_bytes(free),
            }
        )
    return out


def _list_mounts_windows() -> list[dict]:
    out: list[dict] = []
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if not Path(root).exists():
            continue
        usage = _usage_for(root)
        out.append(
            {
                "mountpoint": root.rstrip("\\") + "\\",
                "source": root,
                "fstype": "ntfs",
                **usage,
            }
        )
    return out


def list_mounts() -> list[dict]:
    """Return browsable real disk mounts (deduped by mountpoint)."""
    if platform.system() == "Windows":
        mounts = _list_mounts_windows()
    else:
        mounts = _list_mounts_findmnt() or _list_mounts_df()
        # Always include root if somehow missed
        if not any(m.get("mountpoint") == "/" for m in mounts):
            if Path("/").exists() and not _should_skip_mount("/", "ext4", None):
                mounts.insert(0, {"mountpoint": "/", "source": "root", "fstype": "", **_usage_for("/")})

    # Prefer shorter paths first; dedupe
    seen: set[str] = set()
    unique: list[dict] = []
    for m in sorted(mounts, key=lambda x: (len(str(x.get("mountpoint") or "")), str(x.get("mountpoint") or ""))):
        mp = str(m.get("mountpoint") or "")
        if not mp or mp in seen:
            continue
        # Skip EFI boot partition noise unless it's the only boot mount
        if mp in {"/boot/efi"}:
            continue
        seen.add(mp)
        unique.append(m)
    return unique


def allowed_roots() -> set[str]:
    return {str(m["mountpoint"]) for m in list_mounts() if m.get("mountpoint")}


def normalize_root(root: str) -> str:
    raw = (root or "").strip() or "/"
    if platform.system() == "Windows":
        p = Path(raw)
        if not p.exists():
            raise HTTPException(status_code=400, detail="Unknown mount root.")
        resolved = str(p.resolve())
        # Ensure trailing style consistency for drive roots
        roots = allowed_roots()
        for r in roots:
            if Path(r).resolve() == Path(resolved).resolve() or resolved.startswith(str(Path(r).resolve())):
                # Use the official mountpoint string
                if Path(resolved) == Path(r).resolve():
                    return r
        # If resolved is under a root, still require exact root selection
        if resolved in {str(Path(r).resolve()) for r in roots}:
            for r in roots:
                if str(Path(r).resolve()) == resolved:
                    return r
        raise HTTPException(status_code=400, detail="Mount root is not an allowed disk.")
    # Linux
    if not raw.startswith("/"):
        raise HTTPException(status_code=400, detail="Mount root must be absolute.")
    resolved = str(Path(raw).resolve())
    roots = allowed_roots()
    if resolved not in roots and raw not in roots:
        # Allow exact match after resolve of listed roots
        for r in roots:
            if str(Path(r).resolve()) == resolved:
                return r
        raise HTTPException(status_code=400, detail="Mount root is not an allowed disk.")
    # Prefer the listed mountpoint string
    for r in roots:
        if str(Path(r).resolve()) == resolved:
            return r
    return resolved


def safe_join(root: str, rel: str | None) -> Path:
    """Join root + relative path; refuse escapes and symlink escapes."""
    root_norm = normalize_root(root)
    root_path = Path(root_norm).resolve()
    rel_clean = (rel or "").replace("\\", "/").strip("/")
    if ".." in Path(rel_clean).parts:
        raise HTTPException(status_code=400, detail="Path traversal is not allowed.")
    if rel_clean:
        candidate = (root_path / rel_clean)
    else:
        candidate = root_path
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise HTTPException(status_code=400, detail="Invalid path.") from exc

    root_s = str(root_path)
    res_s = str(resolved)
    if res_s != root_s and not res_s.startswith(root_s.rstrip(os.sep) + os.sep):
        raise HTTPException(status_code=403, detail="Path escapes the selected mount.")

    # If path exists and is a symlink, ensure final resolve still under root
    if candidate.exists() or resolved.exists():
        try:
            final = resolved.resolve(strict=True)
        except OSError:
            final = resolved
        final_s = str(final)
        if final_s != root_s and not final_s.startswith(root_s.rstrip(os.sep) + os.sep):
            raise HTTPException(status_code=403, detail="Symlink escapes the selected mount.")
        return final
    return resolved


def _entry_type(path: Path) -> str:
    try:
        if path.is_symlink():
            # Classify by target
            if path.is_dir():
                return "dir"
            return "file"
        if path.is_dir():
            return "dir"
        return "file"
    except OSError:
        return "file"


def list_dir(root: str, rel: str | None = None, *, limit: int = 500, offset: int = 0) -> dict:
    path = safe_join(root, rel)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Path not found.")
    if not path.is_dir():
        raise HTTPException(status_code=400, detail="Not a directory.")

    # Refuse listing virtual prefixes even if somehow under root
    path_s = str(path).replace("\\", "/")
    if any(path_s == p or path_s.startswith(p + "/") for p in ("/proc", "/sys", "/dev", "/run")):
        raise HTTPException(status_code=403, detail="Virtual filesystem is not browsable.")

    entries: list[dict] = []
    try:
        children = list(path.iterdir())
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="Permission denied.") from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Unable to list directory.") from exc

    for child in children:
        try:
            st = child.lstat()
        except OSError:
            continue
        kind = _entry_type(child)
        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
        entries.append(
            {
                "name": child.name,
                "type": kind,
                "size": int(st.st_size) if kind == "file" and not stat.S_ISLNK(st.st_mode) else None,
                "mtime": mtime,
                "mode": stat.filemode(st.st_mode),
                "is_symlink": bool(stat.S_ISLNK(st.st_mode)),
                "download_blocked": kind == "file" and _is_blocked_download(child),
            }
        )

    entries.sort(key=lambda e: (0 if e["type"] == "dir" else 1, (e["name"] or "").lower()))
    total = len(entries)
    limit = max(1, min(int(limit or 500), 1000))
    offset = max(0, int(offset or 0))
    page = entries[offset : offset + limit]

    root_norm = normalize_root(root)
    rel_clean = (rel or "").replace("\\", "/").strip("/")
    crumbs = []
    if rel_clean:
        parts = rel_clean.split("/")
        acc: list[str] = []
        for part in parts:
            acc.append(part)
            crumbs.append({"name": part, "path": "/".join(acc)})

    return {
        "root": root_norm,
        "path": rel_clean,
        "absolute": str(path),
        "breadcrumbs": crumbs,
        "entries": page,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def resolve_download(root: str, rel: str | None) -> Path:
    path = safe_join(root, rel)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found.")
    if path.is_dir():
        raise HTTPException(status_code=400, detail="Cannot download a directory.")
    if not path.is_file():
        raise HTTPException(status_code=400, detail="Not a regular file.")
    if _is_blocked_download(path):
        raise HTTPException(status_code=403, detail="Download of this file is blocked for security.")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Unable to read file.") from exc
    max_bytes = int(FS_DOWNLOAD_MAX_BYTES or 104857600)
    if size > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds download limit ({_human_bytes(max_bytes)}).",
        )
    return path
