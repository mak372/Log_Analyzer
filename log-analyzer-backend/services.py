import psycopg2
import csv
from collections import defaultdict
import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:MastersUS24!123@localhost/log_analysis"
)

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

def parse_zscaler_log(file_path):
    events = []
    threat_counts = defaultdict(int)

    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 26:
                continue

            event = {
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
            events.append(event)

            if event["threat"] and event["threat"].lower() != "none":
                threat_counts[event["threat"]] += 1

    summary = {
        "total_events": len(events),
        "total_threats": sum(threat_counts.values()),
        "top_threats": dict(sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    }

    return {"summary": summary, "timeline": events}

def save_logs_to_db(events):
    conn = get_db_connection()
    cursor = conn.cursor()

    for event in events:
        cursor.execute(
            '''
            INSERT INTO logs 
            (timestamp, device, protocol, url, action, application, category,
             source_ip, destination_ip, http_method, status_code,
             user_agent, username, threat)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ''',
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
        )

    conn.commit()
    cursor.close()
    conn.close()
