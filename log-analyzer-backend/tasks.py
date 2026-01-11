from celery_app import celery
from services import get_db_connection, parse_zscaler_log, save_logs_to_db
from datetime import datetime

@celery.task(bind=True)
def process_log_file(self, job_id, username, filepath):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE log_jobs SET status=%s, error=NULL WHERE id=%s",
            ('Processing', job_id)
        )
        conn.commit()

        results = parse_zscaler_log(filepath)
        events = results["timeline"]
        save_logs_to_db(events)

        cursor.execute(
            '''
            UPDATE log_jobs
            SET status=%s, progress=%s, completed_at=%s
            WHERE id=%s
            ''',
            ("Completed", 100, datetime.utcnow(), job_id)
        )
        conn.commit()

    except Exception as e:
        cursor.execute(
            "UPDATE log_jobs SET status=%s, error=%s WHERE id=%s",
            ('Failed', str(e), job_id)
        )
        conn.commit()
        raise e
    finally:
        cursor.close()
        conn.close()
