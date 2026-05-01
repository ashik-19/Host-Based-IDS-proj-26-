# log_monitor.py
# Windows Event Log Monitor for PyHIDS
# Reads Windows Security Event Log and detects suspicious activity
# Run this alongside app.py and fim.py

import win32evtlog
import win32evtlogutil
import win32con
import winerror
import os
import time
from datetime import datetime, timedelta
from collections import defaultdict
from database import initialize_database, insert_alert, insert_log_event

# ─── Configuration ────────────────────────────────────────────────────────────

# How often to poll the Event Log for new entries (seconds)
POLL_INTERVAL = 15

# Brute force detection: how many failed logins trigger a CRITICAL alert
BRUTE_FORCE_THRESHOLD = 5

# Brute force detection: time window in seconds
BRUTE_FORCE_WINDOW = 60

# Your machine name — shown in dashboard alerts
HOSTNAME = os.environ.get('COMPUTERNAME', 'localhost')

# Event IDs we care about and their descriptions
WATCHED_EVENT_IDS = {
    4625: 'Failed logon attempt',
    4720: 'New user account created',
    4672: 'Special privileges assigned to logon',
    4698: 'Scheduled task created',
    4732: 'User added to privileged group',
    4719: 'System audit policy changed',
    4964: 'Special groups assigned to new logon',
}


# ─── Brute Force Tracker ──────────────────────────────────────────────────────
class BruteForceTracker:
    """
    Tracks failed login attempts per username/IP combination.
    Uses a sliding time window to detect brute force attacks.

    How it works:
    - Every time a failed login (Event ID 4625) is detected, we store
      the timestamp in a list keyed by the username targeted.
    - When checking, we only count timestamps within the last
      BRUTE_FORCE_WINDOW seconds (sliding window).
    - If the count exceeds BRUTE_FORCE_THRESHOLD, it's a brute force.
    - We track which combos have already been alerted to avoid spam.
    """

    def __init__(self):
        # Dict of username -> list of timestamps of failed attempts
        self.attempts = defaultdict(list)
        # Set of usernames we've already sent a brute force alert for
        # (cleared after window expires so we can re-alert if attack continues)
        self.alerted = set()

    def record_attempt(self, username, source_ip='unknown'):
        """
        Records a failed login attempt for a username.
        Returns True if this attempt triggered a brute force alert.
        """
        now = datetime.now()
        key = f"{username}@{source_ip}"

        # Add this attempt
        self.attempts[key].append(now)

        # Clean up attempts older than our window
        cutoff = now - timedelta(seconds=BRUTE_FORCE_WINDOW)
        self.attempts[key] = [t for t in self.attempts[key] if t > cutoff]

        count = len(self.attempts[key])

        print(f"[LOG] Failed login for '{username}' from {source_ip} "
              f"— {count}/{BRUTE_FORCE_THRESHOLD} in {BRUTE_FORCE_WINDOW}s window")

        # Check if threshold exceeded and we haven't already alerted for this key
        if count >= BRUTE_FORCE_THRESHOLD and key not in self.alerted:
            self.alerted.add(key)
            return True, count

        # If the window has fully expired, remove from alerted so we can re-alert
        if count == 0 and key in self.alerted:
            self.alerted.discard(key)

        return False, count

    def get_attempt_count(self, username, source_ip='unknown'):
        """Returns current attempt count for a username within the window."""
        key = f"{username}@{source_ip}"
        now = datetime.now()
        cutoff = now - timedelta(seconds=BRUTE_FORCE_WINDOW)
        recent = [t for t in self.attempts[key] if t > cutoff]
        return len(recent)


# ─── Event Parsers ────────────────────────────────────────────────────────────

def parse_event_message(event):
    """
    Extracts the full message text from a Windows Event Log record.
    Returns a string with the event message.
    """
    try:
        msg = win32evtlogutil.SafeFormatMessage(event, 'Security')
        return msg if msg else f"Event ID {event.EventID}"
    except Exception:
        return f"Event ID {event.EventID & 0xFFFF}"


def extract_field(message, field_name):
    """
    Extracts a specific field value from an event message string.
    Windows event messages have lines like "Account Name: Administrator"
    This function finds those lines and returns the value.
    """
    lines = message.split('\n')
    for i, line in enumerate(lines):
        if field_name.lower() in line.lower():
            # Value is usually after the colon on the same line
            parts = line.split(':', 1)
            if len(parts) == 2:
                value = parts[1].strip()
                if value and value not in ['-', 'N/A', '%%1833']:
                    return value
    return 'unknown'


def get_event_time(event):
    """Converts a Windows SYSTEMTIME struct to a readable string."""
    try:
        t = event.TimeGenerated
        return datetime(t.year, t.month, t.day,
                        t.hour, t.minute, t.second).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


# ─── Event Handlers ───────────────────────────────────────────────────────────

def handle_failed_login(event, message, tracker):
    """
    Handles Event ID 4625 — Failed logon attempt.
    Records in brute force tracker and alerts if threshold exceeded.
    """
    username  = extract_field(message, 'Account Name')
    source_ip = extract_field(message, 'Source Network Address')
    logon_type = extract_field(message, 'Logon Type')
    event_time = get_event_time(event)

    # Clean up '-' or loopback IPs that aren't meaningful
    if source_ip in ['-', '127.0.0.1', '::1', 'unknown']:
        source_ip = 'local'

    # Always insert a basic WARNING log event
    raw_line = (f"[{event_time}] Failed logon for user '{username}' "
                f"from {source_ip} (Logon Type: {logon_type})")

    insert_log_event(
        source_file='Windows Security Event Log',
        raw_line=raw_line,
        pattern='Event ID 4625 — Failed Logon',
        host=HOSTNAME
    )

    # Check brute force threshold
    is_brute_force, count = tracker.record_attempt(username, source_ip)

    if is_brute_force:
        # Brute force threshold hit — CRITICAL alert
        insert_alert(
            severity='CRITICAL',
            module='LOG_MONITOR',
            title=f'Brute force attack detected on user: {username}',
            description=(f'{count} failed login attempts for user "{username}" '
                         f'from {source_ip} within {BRUTE_FORCE_WINDOW} seconds. '
                         f'Possible brute force or credential stuffing attack.'),
            host=HOSTNAME
        )
        print(f"[LOG] *** CRITICAL: BRUTE FORCE — {count} attempts on '{username}' from {source_ip}")
    else:
        # Single failed login — WARNING alert
        insert_alert(
            severity='WARNING',
            module='LOG_MONITOR',
            title=f'Failed login attempt for user: {username}',
            description=raw_line,
            host=HOSTNAME
        )
        print(f"[LOG] WARNING: Failed login for '{username}' from {source_ip}")


def handle_user_created(event, message):
    """
    Handles Event ID 4720 — A new user account was created.
    This is always suspicious unless expected — CRITICAL alert.
    """
    new_username  = extract_field(message, 'New Account')
    created_by    = extract_field(message, 'Subject Account Name')
    event_time    = get_event_time(event)

    # Sometimes the field names differ — try alternative
    if new_username == 'unknown':
        new_username = extract_field(message, 'Account Name')

    raw_line = (f"[{event_time}] New user account created: '{new_username}' "
                f"by '{created_by}'")

    insert_log_event(
        source_file='Windows Security Event Log',
        raw_line=raw_line,
        pattern='Event ID 4720 — New User Account Created',
        host=HOSTNAME
    )

    insert_alert(
        severity='CRITICAL',
        module='LOG_MONITOR',
        title=f'New user account created: {new_username}',
        description=(f'A new Windows user account "{new_username}" was created '
                     f'by "{created_by}" at {event_time}. '
                     f'Verify this was an authorized action.'),
        host=HOSTNAME
    )
    print(f"[LOG] *** CRITICAL: New user created — '{new_username}' by '{created_by}'")


def handle_privilege_assigned(event, message):
    """
    Handles Event ID 4672 — Special privileges assigned.
    Fires when an account logs on with admin-level privileges.
    """
    username   = extract_field(message, 'Account Name')
    privileges = extract_field(message, 'Privileges')
    event_time = get_event_time(event)

    # Filter out SYSTEM and LOCAL SERVICE — those are normal
    if username.upper() in ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE',
                             'ANONYMOUS LOGON']:
        return

    raw_line = (f"[{event_time}] Special privileges assigned to '{username}': "
                f"{privileges[:80] if privileges != 'unknown' else 'see event log'}")

    insert_log_event(
        source_file='Windows Security Event Log',
        raw_line=raw_line,
        pattern='Event ID 4672 — Special Privileges Assigned',
        host=HOSTNAME
    )

    insert_alert(
        severity='WARNING',
        module='LOG_MONITOR',
        title=f'Privilege escalation: special privileges for {username}',
        description=(f'User "{username}" was assigned special privileges at {event_time}. '
                     f'Privileges: {privileges[:120] if privileges != "unknown" else "SeDebugPrivilege and others"}'),
        host=HOSTNAME
    )
    print(f"[LOG] WARNING: Special privileges assigned to '{username}'")


def handle_scheduled_task(event, message):
    """
    Handles Event ID 4698 — A scheduled task was created.
    Attackers often use scheduled tasks for persistence.
    """
    task_name  = extract_field(message, 'Task Name')
    created_by = extract_field(message, 'Subject Account Name')
    event_time = get_event_time(event)

    raw_line = (f"[{event_time}] Scheduled task created: '{task_name}' "
                f"by '{created_by}'")

    insert_log_event(
        source_file='Windows Security Event Log',
        raw_line=raw_line,
        pattern='Event ID 4698 — Scheduled Task Created',
        host=HOSTNAME
    )

    insert_alert(
        severity='WARNING',
        module='LOG_MONITOR',
        title=f'Scheduled task created: {task_name}',
        description=(f'A new scheduled task "{task_name}" was created by '
                     f'"{created_by}" at {event_time}. '
                     f'Verify this is an authorized scheduled task.'),
        host=HOSTNAME
    )
    print(f"[LOG] WARNING: Scheduled task created — '{task_name}' by '{created_by}'")


def handle_admin_group_change(event, message):
    """
    Handles Event ID 4732 — User added to a privileged group.
    """
    username   = extract_field(message, 'Member Name')
    group_name = extract_field(message, 'Group Name')
    changed_by = extract_field(message, 'Subject Account Name')
    event_time = get_event_time(event)

    raw_line = (f"[{event_time}] User '{username}' added to group "
                f"'{group_name}' by '{changed_by}'")

    insert_log_event(
        source_file='Windows Security Event Log',
        raw_line=raw_line,
        pattern='Event ID 4732 — User Added to Privileged Group',
        host=HOSTNAME
    )

    insert_alert(
        severity='CRITICAL',
        module='LOG_MONITOR',
        title=f'User added to privileged group: {group_name}',
        description=(f'"{username}" was added to the security group '
                     f'"{group_name}" by "{changed_by}" at {event_time}. '
                     f'If this was not authorized, investigate immediately.'),
        host=HOSTNAME
    )
    print(f"[LOG] *** CRITICAL: '{username}' added to group '{group_name}'")


# ─── Main Event Processor ─────────────────────────────────────────────────────

def process_event(event, tracker):
    """
    Receives a single Event Log record and dispatches it
    to the correct handler based on its Event ID.
    """
    # Mask the event ID to get the actual number
    # (Windows stores some flags in the upper bits)
    event_id = event.EventID & 0xFFFF

    if event_id not in WATCHED_EVENT_IDS:
        return  # Not an event we care about

    try:
        message = parse_event_message(event)
    except Exception as e:
        message = f"Could not parse message: {e}"

    print(f"[LOG] Event ID {event_id}: {WATCHED_EVENT_IDS[event_id]}")

    if event_id == 4625:
        handle_failed_login(event, message, tracker)
    elif event_id == 4720:
        handle_user_created(event, message)
    elif event_id == 4672:
        handle_privilege_assigned(event, message)
    elif event_id == 4698:
        handle_scheduled_task(event, message)
    elif event_id == 4732:
        handle_admin_group_change(event, message)
    else:
        # Generic handler for other watched event IDs
        raw_line = f"Event ID {event_id}: {WATCHED_EVENT_IDS[event_id]} at {get_event_time(event)}"
        insert_log_event(
            source_file='Windows Security Event Log',
            raw_line=raw_line,
            pattern=f'Event ID {event_id}',
            host=HOSTNAME
        )
        insert_alert(
            severity='WARNING',
            module='LOG_MONITOR',
            title=f'Security event detected: {WATCHED_EVENT_IDS[event_id]}',
            description=raw_line,
            host=HOSTNAME
        )


# ─── Event Log Reader ─────────────────────────────────────────────────────────

def read_new_events(log_handle, last_record_id):
    """
    Reads all new events from the Security Event Log
    since the last record we processed.

    Returns a list of new events and the new last_record_id.
    """
    new_events = []
    new_last_id = last_record_id

    flags = (win32con.EVENTLOG_FORWARDS_READ |
             win32con.EVENTLOG_SEQUENTIAL_READ)

    while True:
        try:
            events = win32evtlog.ReadEventLog(log_handle, flags, 0)
            if not events:
                break

            for event in events:
                record_id = event.RecordNumber

                # Only process events we haven't seen yet
                if record_id > last_record_id:
                    new_events.append(event)
                    if record_id > new_last_id:
                        new_last_id = record_id

        except Exception as e:
            if hasattr(e, 'winerror') and e.winerror == winerror.ERROR_HANDLE_EOF:
                break  # Reached end of log — normal
            else:
                print(f"[LOG] Error reading event log: {e}")
                break

    return new_events, new_last_id


def get_current_record_id(log_handle):
    """
    Gets the ID of the most recent record in the event log.
    We use this as our starting point so we only process NEW events
    and don't re-process the entire log history on startup.
    """
    flags = (win32con.EVENTLOG_BACKWARDS_READ |
             win32con.EVENTLOG_SEQUENTIAL_READ)
    try:
        events = win32evtlog.ReadEventLog(log_handle, flags, 0)
        if events:
            return events[0].RecordNumber
    except Exception:
        pass
    return 0


# ─── Main Monitor Loop ────────────────────────────────────────────────────────

def start_log_monitor():
    """
    Main entry point for the Windows Log Monitor.
    Opens the Security Event Log and polls for new events every POLL_INTERVAL seconds.
    """
    print("[LOG] Initializing database...")
    initialize_database()

    print(f"[LOG] Starting Windows Log Monitor on {HOSTNAME}")
    print(f"[LOG] Watching Event IDs: {list(WATCHED_EVENT_IDS.keys())}")
    print(f"[LOG] Brute force threshold: {BRUTE_FORCE_THRESHOLD} attempts in {BRUTE_FORCE_WINDOW}s")
    print(f"[LOG] Poll interval: {POLL_INTERVAL} seconds")
    print("[LOG] ─────────────────────────────────────────")

    # Initialize brute force tracker
    tracker = BruteForceTracker()

    # Open the Windows Security Event Log
    try:
        log_handle = win32evtlog.OpenEventLog(None, 'Security')
        print("[LOG] ✓ Security Event Log opened successfully")
    except Exception as e:
        print(f"[LOG] ERROR: Cannot open Security Event Log: {e}")
        print("[LOG] Try running this script as Administrator.")
        print("[LOG] Right-click CMD → Run as administrator → activate venv → python log_monitor.py")
        return

    # Get the current latest record ID so we start from NOW, not from the beginning
    last_record_id = get_current_record_id(log_handle)
    print(f"[LOG] Starting from record ID: {last_record_id}")
    print(f"[LOG] ✓ Monitoring active. Polling every {POLL_INTERVAL}s. Press Ctrl+C to stop.")

    # Insert a startup info alert so you can see the monitor is running on the dashboard
    insert_alert(
        severity='INFO',
        module='LOG_MONITOR',
        title='Windows Log Monitor started',
        description=(f'Log monitor is now active on {HOSTNAME}. '
                     f'Watching for Event IDs: {list(WATCHED_EVENT_IDS.keys())}. '
                     f'Brute force detection: {BRUTE_FORCE_THRESHOLD} attempts in {BRUTE_FORCE_WINDOW}s.'),
        host=HOSTNAME
    )

    try:
        while True:
            new_events, last_record_id = read_new_events(log_handle, last_record_id)

            if new_events:
                print(f"[LOG] {len(new_events)} new event(s) to process...")
                for event in new_events:
                    process_event(event, tracker)
            else:
                # Print a heartbeat every poll so you know it's running
                print(f"[LOG] Heartbeat — no new security events "
                      f"({datetime.now().strftime('%H:%M:%S')})")

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n[LOG] Stopping log monitor...")
    finally:
        win32evtlog.CloseEventLog(log_handle)
        print("[LOG] Event log closed. Stopped.")


if __name__ == '__main__':
    start_log_monitor()