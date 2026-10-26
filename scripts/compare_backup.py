# -*- coding: utf-8 -*-
import os
import zipfile
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKUP_PATH = ROOT / "backup.zip"

EXCLUDE_DIRS = {
    "node_modules",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "slide_renders",
    "template_images",
}
EXCLUDE_FILES = {
    "backup.zip",
    "backup.zip.bak",
}

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def get_workspace_files():
    files = {}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        # Filter dirnames in place
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for f in filenames:
            if f in EXCLUDE_FILES:
                continue
            full_p = Path(dirpath) / f
            rel_p = full_p.relative_to(ROOT).as_posix()
            files[rel_p] = full_p
    return files

def compare():
    print(f"Reading backup.zip from {BACKUP_PATH}...")
    z = zipfile.ZipFile(BACKUP_PATH, "r")
    backup_entries = {}
    for info in z.infolist():
        if info.is_dir():
            continue
        norm_name = info.filename.replace("\\", "/")
        # skip excluded
        parts = norm_name.split("/")
        if any(p in EXCLUDE_DIRS for p in parts) or norm_name in EXCLUDE_FILES:
            continue
        backup_entries[norm_name] = info

    ws_files = get_workspace_files()

    only_in_backup = []
    only_in_workspace = []
    modified_files = []
    identical_files = []

    all_keys = sorted(set(backup_entries.keys()) | set(ws_files.keys()))

    for key in all_keys:
        in_backup = key in backup_entries
        in_ws = key in ws_files

        if in_backup and not in_ws:
            only_in_backup.append(key)
        elif in_ws and not in_backup:
            only_in_workspace.append(key)
        else:
            # In both, compare content
            b_data = z.read(backup_entries[key])
            b_hash = sha256_bytes(b_data)
            ws_hash = sha256_file(ws_files[key])
            if b_hash != ws_hash:
                modified_files.append((key, len(b_data), ws_files[key].stat().st_size))
            else:
                identical_files.append(key)

    print("\n" + "="*70)
    print("BACKUP.ZIP VS CURRENT WORKSPACE COMPARISON SUMMARY")
    print("="*70)
    print(f"Total files in backup.zip:        {len(backup_entries)}")
    print(f"Total files in current workspace: {len(ws_files)}")
    print(f"Identical files:                  {len(identical_files)}")
    print(f"Modified files (differing):       {len(modified_files)}")
    print(f"New files in workspace (missing in backup): {len(only_in_workspace)}")
    print(f"Deleted files in workspace (only in backup): {len(only_in_backup)}")

    print("\n" + "-"*70)
    print(f"1. MODIFIED FILES ({len(modified_files)}):")
    print("-"*70)
    for k, b_sz, w_sz in modified_files:
        print(f"  * {k:50} (backup: {b_sz:>8} bytes -> ws: {w_sz:>8} bytes)")

    print("\n" + "-"*70)
    print(f"2. NEW FILES IN WORKSPACE (NOT IN BACKUP) ({len(only_in_workspace)}):")
    print("-"*70)
    for k in only_in_workspace:
        sz = ws_files[k].stat().st_size
        print(f"  + {k:50} ({sz:>8} bytes)")

    print("\n" + "-"*70)
    print(f"3. FILES ONLY IN BACKUP (DELETED/MISSING IN WS) ({len(only_in_backup)}):")
    print("-"*70)
    for k in only_in_backup:
        print(f"  - {k}")

if __name__ == "__main__":
    compare()
