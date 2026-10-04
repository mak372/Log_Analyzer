"""Storage consumer: reads raw log lines from Kafka, parses them and batch-inserts them into Postgres.

Run with:  python consumer_storage.py
Offsets are committed only after the database commit, so a crash replays the last batch
instead of losing it (at-least-once delivery).
"""
import logging
import signal
import time
from collections import Counter

from confluent_kafka import KafkaError, KafkaException

from kafka_client import RAW_LOGS_TOPIC, create_consumer, decode_message, ensure_topics
from services import get_db_connection, parse_zscaler_line, save_logs_to_db, record_job_progress

logging.basicConfig(level=logging.INFO, format="%(asctime)s [storage] %(message)s")
logger = logging.getLogger(__name__)

GROUP_ID = "log-storage"
BATCH_SIZE = 500
POLL_TIMEOUT = 1.0
RETRY_DELAY = 5

running = True


def stop(*_):
    global running
    running = False


def reconnect(conn):
    try:
        conn.close()
    except Exception:
        pass
    time.sleep(RETRY_DELAY)
    try:
        return get_db_connection()
    except Exception:
        logger.exception("Database reconnect failed")
        return conn


def process_batch(messages, conn):
    events = []
    job_counts = Counter()

    for msg in messages:
        try:
            payload = decode_message(msg)
        except ValueError:
            logger.warning("Skipping message with invalid JSON at offset %s", msg.offset())
            continue

        event = parse_zscaler_line(payload.get("line"))
        if event is not None:
            events.append(event)
        # Count every message for its job, even unparseable ones, so the job can still complete.
        if payload.get("job_id"):
            job_counts[payload["job_id"]] += 1

    save_logs_to_db(events, conn=conn)
    cursor = conn.cursor()
    for job_id, count in job_counts.items():
        record_job_progress(cursor, job_id, count)
    cursor.close()
    conn.commit()
    return len(events)


def main():
    ensure_topics()
    consumer = create_consumer(GROUP_ID)
    consumer.subscribe([RAW_LOGS_TOPIC])
    conn = get_db_connection()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    logger.info("Consuming %s as group %s", RAW_LOGS_TOPIC, GROUP_ID)

    try:
        while running:
            messages = consumer.consume(num_messages=BATCH_SIZE, timeout=POLL_TIMEOUT)
            valid = []
            for msg in messages:
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error("Kafka error: %s", msg.error())
                    continue
                valid.append(msg)
            if not valid:
                continue

            # Retry the same batch until Postgres accepts it; offsets aren't committed until it does.
            while True:
                try:
                    stored = process_batch(valid, conn)
                    break
                except Exception:
                    logger.exception("Failed to store batch; retrying in %ss", RETRY_DELAY)
                    conn = reconnect(conn)
                    if not running:
                        return

            try:
                consumer.commit(asynchronous=False)
            except KafkaException as e:
                # Happens if a long DB outage caused a rebalance; the batch will be redelivered.
                logger.warning("Offset commit failed: %s", e)
            logger.info("Stored %d events from %d messages", stored, len(valid))
    finally:
        consumer.close()
        conn.close()
        logger.info("Stopped")


if __name__ == "__main__":
    main()
