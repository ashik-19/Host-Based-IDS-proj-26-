# fim.py
# File Integrity Monitor for PyHIDS
# Watches configured directories for file changes using SHA-256 hashing
# Run this alongside app.py — they both connect to the same SQLite database

import hashlib
import os
import time
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from database import (initialize_database, get_baseline_hash,
                      set_baseline_hash, insert_fim_event, insert_alert)

# ─── Configuration ────────────────────────────────────────────────────────────
# Add any folders you want to monitor to this list.
# Use raw strings (r"...") to avoid backslash issues on Windows.
WATCHED_PATHS = [
    r"C:\PyHIDS_watched",        # test folder we will create in Step 3
    r"C:\Users\Public\Documents", # public documents folder
]

# Files in these paths generate CRITICAL alerts (more sensitive)
CRITICAL_PATHS = [
    r"C:\Windows\System32",
    r"C:\Windows\System",
    r"C:\PyHIDS_watched",  # treating our test folder as critical for demo
]

# File extensions to ignore (temp files, lock files, etc.)
IGNORED_EXTENSIONS = ['.tmp', '.lock', '.log', '~', '.swp', '.part']

# Your machine's hostname — shown in dashboard alerts
HOSTNAME = os.environ.get('COMPUTERNAME', 'localhost')


# ─── Hash Function ────────────────────────────────────────────────────────────
def compute_sha256(filepath):
    """
    Computes the SHA-256 hash of a file.
    Returns the hex digest string, or None if the file can't be read
    (e.g. it was deleted between detection and hashing, or access denied).
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            # Read in 64KB chunks so large files don't fill memory
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"[FIM] Cannot hash {filepath}: {e}")
        return None


# ─── Severity Helper ──────────────────────────────────────────────────────────
def get_severity(filepath):
    """
    Returns CRITICAL if the file is in a sensitive path, WARNING otherwise.
    """
    for critical_path in CRITICAL_PATHS:
        if filepath.startswith(critical_path):
            return 'CRITICAL'
    return 'WARNING'


# ─── Should Ignore ────────────────────────────────────────────────────────────
def should_ignore(filepath):
    """
    Returns True if this file should be skipped.
    Ignores temp files and hidden system files.
    """
    _, ext = os.path.splitext(filepath)
    if ext.lower() in IGNORED_EXTENSIONS:
        return True
    # Ignore files starting with . (hidden files)
    basename = os.path.basename(filepath)
    if basename.startswith('.'):
        return True
    return False


# ─── Baseline Scanner ─────────────────────────────────────────────────────────
def build_baseline(paths):
    """
    Scans all files in the watched paths and stores their SHA-256 hashes
    as the baseline (known good state). Only runs if no baseline exists yet.
    """
    print("[FIM] Building baseline hashes for watched paths...")
    total = 0
    for watch_path in paths:
        if not os.path.exists(watch_path):
            print(f"[FIM] WARNING: Path does not exist, skipping: {watch_path}")
            continue

        for root, dirs, files in os.walk(watch_path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            for filename in files:
                filepath = os.path.join(root, filename)

                if should_ignore(filepath):
                    continue

                # Only set baseline if we don't already have one for this file
                existing = get_baseline_hash(filepath)
                if existing is None:
                    hash_value = compute_sha256(filepath)
                    if hash_value:
                        set_baseline_hash(filepath, hash_value)
                        total += 1
                        print(f"[FIM] Baselined: {filepath}")

    print(f"[FIM] Baseline complete. {total} new files registered.")


# ─── Event Handler ────────────────────────────────────────────────────────────
class HIDSEventHandler(FileSystemEventHandler):
    """
    Handles filesystem events detected by Watchdog.
    Watchdog calls these methods automatically when files change.
    """

    def on_created(self, event):
        """Called when a new file is created in a watched directory."""
        if event.is_directory:
            return
        filepath = event.src_path
        if should_ignore(filepath):
            return

        print(f"[FIM] FILE CREATED: {filepath}")

        # Small delay to let the file finish writing before we hash it
        time.sleep(0.5)

        new_hash = compute_sha256(filepath)
        if new_hash is None:
            return

        # Store as new baseline
        set_baseline_hash(filepath, new_hash)

        # Determine severity — new files in critical paths are more suspicious
        severity = get_severity(filepath)

        # Save to fim_events table
        insert_fim_event(
            filepath=filepath,
            event_type='created',
            old_hash=None,
            new_hash=new_hash,
            host=HOSTNAME
        )

        # Also create an alert so it shows on the dashboard
        insert_alert(
            severity=severity,
            module='FIM',
            title=f'New file created: {os.path.basename(filepath)}',
            description=f'A new file was created at {filepath}. '
                        f'SHA-256: {new_hash[:16]}...',
            host=HOSTNAME
        )
        print(f"[FIM] ALERT ({severity}): New file created — {filepath}")


    def on_modified(self, event):
        """Called when an existing file is modified."""
        if event.is_directory:
            return
        filepath = event.src_path
        if should_ignore(filepath):
            return

        # Small delay — on_modified can fire twice for a single save
        time.sleep(0.3)

        new_hash = compute_sha256(filepath)
        if new_hash is None:
            return

        old_hash = get_baseline_hash(filepath)

        # If we have no baseline for this file, just store the hash and move on
        if old_hash is None:
            set_baseline_hash(filepath, new_hash)
            return

        # If hash hasn't changed, ignore — some editors trigger spurious events
        if old_hash == new_hash:
            return

        print(f"[FIM] FILE MODIFIED: {filepath}")
        print(f"[FIM]   Old hash: {old_hash[:24]}...")
        print(f"[FIM]   New hash: {new_hash[:24]}...")

        severity = get_severity(filepath)

        # Update baseline to the new hash
        set_baseline_hash(filepath, new_hash)

        insert_fim_event(
            filepath=filepath,
            event_type='modified',
            old_hash=old_hash,
            new_hash=new_hash,
            host=HOSTNAME
        )

        insert_alert(
            severity=severity,
            module='FIM',
            title=f'File modified: {os.path.basename(filepath)}',
            description=f'File content changed at {filepath}. '
                        f'Hash: {old_hash[:12]}... → {new_hash[:12]}...',
            host=HOSTNAME
        )
        print(f"[FIM] ALERT ({severity}): File modified — {filepath}")


    def on_deleted(self, event):
        """Called when a file is deleted from a watched directory."""
        if event.is_directory:
            return
        filepath = event.src_path
        if should_ignore(filepath):
            return

        print(f"[FIM] FILE DELETED: {filepath}")

        old_hash = get_baseline_hash(filepath)
        severity = get_severity(filepath)

        insert_fim_event(
            filepath=filepath,
            event_type='deleted',
            old_hash=old_hash,
            new_hash=None,
            host=HOSTNAME
        )

        insert_alert(
            severity=severity,
            module='FIM',
            title=f'File deleted: {os.path.basename(filepath)}',
            description=f'A monitored file was deleted: {filepath}. '
                        f'Last known hash: {old_hash[:16] if old_hash else "unknown"}...',
            host=HOSTNAME
        )
        print(f"[FIM] ALERT ({severity}): File deleted — {filepath}")


# ─── Main Monitor Loop ────────────────────────────────────────────────────────
def start_fim():
    """
    Starts the File Integrity Monitor.
    Sets up Watchdog observers for all watched paths and runs indefinitely.
    """
    print("[FIM] Initializing database...")
    initialize_database()

    print(f"[FIM] Starting File Integrity Monitor on {HOSTNAME}")
    print(f"[FIM] Watching {len(WATCHED_PATHS)} path(s):")
    for p in WATCHED_PATHS:
        print(f"[FIM]   → {p}")

    # Build baseline for any files not yet hashed
    build_baseline(WATCHED_PATHS)

    # Create one Watchdog observer and attach handlers for each path
    observer = Observer()
    event_handler = HIDSEventHandler()

    for watch_path in WATCHED_PATHS:
        if os.path.exists(watch_path):
            # recursive=True means it watches subdirectories too
            observer.schedule(event_handler, watch_path, recursive=True)
            print(f"[FIM] Observer attached to: {watch_path}")
        else:
            print(f"[FIM] Skipping non-existent path: {watch_path}")

    observer.start()
    print("[FIM] ✓ Monitoring active. Press Ctrl+C to stop.")
    print("[FIM] ─────────────────────────────────────────")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[FIM] Stopping observer...")
        observer.stop()

    observer.join()
    print("[FIM] Stopped.")


if __name__ == '__main__':
    start_fim()

    