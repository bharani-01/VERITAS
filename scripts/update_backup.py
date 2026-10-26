# -*- coding: utf-8 -*-
"""
Safely update backup.zip to synchronize with the current workspace.
Preserves existing backup as backup_previous.zip before atomic replacement.
Excludes virtual environments, caches, node_modules, and temporary lock files.
"""
from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKUP_PATH = ROOT / "backup.zip"
BACKUP_PREV = ROOT / "backup_previous.zip"
BACKUP_NEW = ROOT / "backup_new.zip"

EXCLUDE_DIRS = {
    "node_modules",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "slide_renders",
    "template_images",
}

EXCLUDE_FILE_PATTERNS = {
    "backup.zip",
    "backup_previous.zip",
    "backup_new.zip",
    "backup.zip.bak",
}

def should_exclude_file(path: Path) -> bool:
    name = path.name
    if name in EXCLUDE_FILE_PATTERNS:
        return True
    if name.startswith("~$"):  # Temporary Office lock files
        return True
    if name.endswith((".pyc", ".pyo")):
        return True
    return False

def update_backup():
    print(f"Project root: {ROOT}")
    print(f"Original backup size: {BACKUP_PATH.stat().st_size / (1024*1024):.2f} MB")
    
    # Step 1: Backup the previous backup
    if BACKUP_PATH.exists() and not BACKUP_PREV.exists():
        print(f"Creating safety copy: {BACKUP_PREV.name}...")
        shutil.copy2(BACKUP_PATH, BACKUP_PREV)
    
    # Step 2: Create new updated zip
    print(f"Packing updated codebase into {BACKUP_NEW.name}...")
    file_count = 0
    total_bytes = 0
    
    with zipfile.ZipFile(BACKUP_NEW, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z_out:
        for dirpath, dirnames, filenames in os.walk(ROOT):
            # Exclude directories in-place
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
            
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                if should_exclude_file(fpath):
                    continue
                
                rel_path = fpath.relative_to(ROOT).as_posix()
                z_out.write(fpath, arcname=rel_path)
                file_count += 1
                total_bytes += fpath.stat().st_size
                
    print(f"Added {file_count} files ({total_bytes / (1024*1024):.2f} MB uncompressed)")
    print(f"New compressed archive size: {BACKUP_NEW.stat().st_size / (1024*1024):.2f} MB")
    
    # Step 3: Verify the new zip can be read cleanly
    print("Verifying new archive integrity...")
    with zipfile.ZipFile(BACKUP_NEW, "r") as z_verify:
        test_res = z_verify.testzip()
        if test_res is not None:
            raise RuntimeError(f"Zip verification failed on file: {test_res}")
        verified_count = len(z_verify.namelist())
        print(f"Integrity verified! Total archive entries: {verified_count}")
        
    # Step 4: Atomic replacement
    print("Performing atomic replacement of backup.zip...")
    if BACKUP_PATH.exists():
        BACKUP_PATH.unlink()
    shutil.move(BACKUP_NEW, BACKUP_PATH)
    print(f"Successfully updated {BACKUP_PATH}!")

if __name__ == "__main__":
    update_backup()
