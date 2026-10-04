import psycopg2
from psycopg2.extras import execute_values
import csv
from collections import defaultdict
import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:MastersUS24!123@localhost/log_analysis"
)

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

def _row_to_event(row):
    if not row or len(row) < 26:
        return None

    return {
        "timestamp": row[0],
        "device": row[1],
        "protocol": row[2],
        "url": row[3],
        "action": row[4],
        "application": row[5],
        "category": row[6],
        "source_ip": row[21],
        "destination_ip": row[22],
        "http_method": row[23],
        "status_code": row[24],
        "user_agent": row[25],
        "user": row[19],
        "threat": row[14]
    }

def parse_zscaler_line(line):
    """Parse a single raw Zscaler CSV line. Returns an event dict, or None if the line is invalid."""
    if not line or not line.strip():
        return None
    try:
        row = next(csv.reader([line]))
    except (csv.Error, StopIteration):
        return None
    return _row_to_event(row)

def is_threat(event):
    threat = event.get("threat")
    return bool(threat) and threat.strip().lower() != "none"

def parse_zscaler_log(file_path):
    events = []
    threat_counts = defaultdict(int)

    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            event = _row_to_event(row)
            if event is None:
                continue
            events.append(event)

            if is_threat(event):
                threat_counts[event["threat"]] += 1

    summary = {
        "total_events": len(events),
        "total_threats": sum(threat_counts.values()),
        "top_threats": dict(sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    }

    return {"summary": summary, "timeline": events}

def save_logs_to_db(events, conn=None):
    """Batch-insert events. Pass an open connection to reuse it (the caller then owns commit/close)."""
    if not events:
        return 0

    owns_conn = conn is None
    if owns_conn:
        conn = get_db_connection()
    cursor = conn.cursor()

    rows = [
        (
            event["timestamp"],
            event["device"],
            event["protocol"],
            event["url"],
            event["action"],
            event["application"],
            event["category"],
            event["source_ip"],
            event["destination_ip"],
            event["http_method"],
            event["status_code"],
            event["user_agent"],
            event["user"],
            event["threat"]
        )
        for event in events
    ]
    execute_values(
        cursor,
        '''
        INSERT INTO logs
        (timestamp, device, protocol, url, action, application, category,
         source_ip, destination_ip, http_method, status_code,
         user_agent, username, threat)
        VALUES %s
        ''',
        rows,
        page_size=500
    )

    cursor.close()
    if owns_conn:
        conn.commit()
        conn.close()
    return len(rows)

def record_job_progress(cursor, job_id, processed):
    """Add `processed` events to a job's count and mark it Completed once every produced event is stored.

    total_events is set by the producer after it finishes sending; until then the job stays Processing.
    Postgres row locking serializes this with the producer's update, so whichever runs last completes the job.
    """
    cursor.execute(
        '''
        UPDATE log_jobs
        SET processed_events = processed_events + %(n)s,
            progress = CASE
                WHEN total_events > 0 THEN LEAST(100, (processed_events + %(n)s) * 100 / total_events)
                ELSE progress END,
            status = CASE
                WHEN total_events IS NOT NULL AND processed_events + %(n)s >= total_events THEN 'Completed'
                ELSE status END,
            completed_at = CASE
                WHEN total_events IS NOT NULL AND processed_events + %(n)s >= total_events
                     AND completed_at IS NULL THEN NOW()
                ELSE completed_at END
        WHERE id = %(id)s AND status <> 'Failed'
        ''',
        {"n": processed, "id": job_id}
    )
