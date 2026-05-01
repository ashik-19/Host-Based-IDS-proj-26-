# app.py
# Main Flask application for PyHIDS dashboard
# Run this file to start the web server

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from database import initialize_database, insert_alert, get_all_alerts, get_alert_counts, get_fim_events, get_log_events
import os

app = Flask(__name__)
CORS(app)  # Allow requests from React/Antigravity frontend later


# ─── Page Routes ─────────────────────────────────────────────────────────────
# These routes serve HTML pages that users see in the browser

@app.route('/')
def index():
    """
    Main dashboard page — shows alert feed and summary metrics.
    """
    alerts = get_all_alerts(limit=50)
    counts = get_alert_counts()
    return render_template('index.html', alerts=alerts, counts=counts)


@app.route('/fim')
def fim_page():
    """
    File Integrity Monitor page — shows all file change events.
    """
    events = get_fim_events(limit=50)
    return render_template('fim.html', events=events)


@app.route('/logs')
def logs_page():
    """
    Log Monitor page — shows suspicious log lines caught from Windows/Debian.
    """
    events = get_log_events(limit=50)
    return render_template('logs.html', events=events)


# ─── API Routes ───────────────────────────────────────────────────────────────
# These routes return JSON data — used by the Debian agent and later by React

@app.route('/api/alerts')
def api_alerts():
    """
    Returns all recent alerts as JSON.
    Your Debian agent will also use this endpoint to check in.
    """
    alerts = get_all_alerts(limit=100)
    counts = get_alert_counts()
    return jsonify({
        'alerts': alerts,
        'counts': counts
    })


@app.route('/api/ingest', methods=['POST'])
def api_ingest():
    """
    Receives log data from the Debian VM agent.
    The agent POSTs JSON here every 10 seconds.
    We'll build the full parsing logic on Day 4.
    For now it just prints what it receives.
    """
    data = request.json
    if not data:
        return jsonify({'error': 'No data received'}), 400

    host = data.get('host', 'unknown-host')
    logs = data.get('logs', '')

    print(f"[AGENT] Received log data from {host}")
    print(f"[AGENT] Log preview: {logs[:200]}")

    # On Day 4 we will add real parsing logic here
    # For now just acknowledge receipt
    return jsonify({'status': 'received', 'host': host})


@app.route('/api/test-alert', methods=['POST'])
def api_test_alert():
    """
    Inserts a manual test alert. Useful for testing the dashboard.
    Call this with: curl -X POST http://localhost:5000/api/test-alert
    """
    insert_alert(
        severity='WARNING',
        module='MANUAL',
        title='Manual test alert triggered',
        description='This alert was manually triggered via the API to test the dashboard.',
        host='localhost'
    )
    return jsonify({'status': 'Test alert inserted'})


# ─── Start Server ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("[HIDS] Initializing database...")
    initialize_database()

    print("[HIDS] Starting PyHIDS dashboard server...")
    print("[HIDS] Open your browser and go to: http://localhost:5000")
    print("[HIDS] Press Ctrl+C to stop the server")

    # debug=True means Flask auto-reloads when you save a file
    # host='0.0.0.0' means it's accessible from your Debian VM too
    app.run(debug=True, host='0.0.0.0', port=5000)