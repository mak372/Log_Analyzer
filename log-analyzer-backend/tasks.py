from celery_app import celery
from services import get_db_connection, parse_zscaler_line
from kafka_client import produce_raw_log, flush_producer

@celery.task(bind=True)
def process_log_file(self, job_id, username, filepath):
    """Stream an uploaded file into Kafka line by line.

    Parsing and storage happen in consumer_storage.py, which marks the job Completed
    once processed_events reaches total_events.
    """
    job_id = str(job_id)
    conn = get_db_connection()
    cursor = conn.cursor()
    delivery_errors = []

    def on_delivery(err, msg):
        if err is not None:
            delivery_errors.append(str(err))

    try:
        cursor.execute(
            "UPDATE log_jobs SET status=%s, error=NULL, processed_events=0, total_events=NULL WHERE id=%s",
            ('Processing', job_id)
        )
        conn.commit()

        sent = 0
        with open(filepath, 'r', newline='') as f:
            for line in f:
                event = parse_zscaler_line(line)
                if event is None:
                    continue
                produce_raw_log(
                    line.rstrip('\r\n'),
                    source='upload',
                    job_id=job_id,
                    key=event["source_ip"],
                    on_delivery=on_delivery,
                )
                sent += 1

        undelivered = flush_producer()
        if undelivered or delivery_errors:
            first_error = delivery_errors[0] if delivery_errors else 'timeout'
            raise RuntimeError(
                f"{undelivered + len(delivery_errors)} events failed to reach Kafka ({first_error})"
            )

        # The storage consumer may already have stored everything, so complete the job here if so.
        cursor.execute(
            '''
            UPDATE log_jobs
            SET total_events = %(total)s,
                progress = CASE WHEN %(total)s > 0 THEN LEAST(100, processed_events * 100 / %(total)s) ELSE 100 END,
                status = CASE WHEN processed_events >= %(total)s THEN 'Completed' ELSE status END,
                completed_at = CASE WHEN processed_events >= %(total)s THEN NOW() ELSE completed_at END
            WHERE id = %(id)s
            ''',
            {"total": sent, "id": job_id}
        )
        conn.commit()

    except Exception as e:
        conn.rollback()
        cursor.execute(
            "UPDATE log_jobs SET status=%s, error=%s WHERE id=%s",
            ('Failed', str(e), job_id)
        )
        conn.commit()
        raise e
    finally:
        cursor.close()
        conn.close()
