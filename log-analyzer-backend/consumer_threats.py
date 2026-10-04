"""Threat consumer: reads the raw log stream independently of storage and publishes
events with a real threat to the threat alerts topic.

Run with:  python consumer_threats.py
"""
import logging
import signal

from confluent_kafka import KafkaError, KafkaException

from kafka_client import (
    RAW_LOGS_TOPIC, THREAT_ALERTS_TOPIC,
    create_consumer, decode_message, ensure_topics, produce_json, flush_producer,
)
from services import parse_zscaler_line, is_threat

logging.basicConfig(level=logging.INFO, format="%(asctime)s [threats] %(message)s")
logger = logging.getLogger(__name__)

GROUP_ID = "threat-detector"
BATCH_SIZE = 500
POLL_TIMEOUT = 1.0

running = True


def stop(*_):
    global running
    running = False


def main():
    ensure_topics()
    # Start from the latest messages: alerts are about what's happening now, not a replay of history.
    consumer = create_consumer(GROUP_ID, auto_offset_reset="latest")
    consumer.subscribe([RAW_LOGS_TOPIC])

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    logger.info("Consuming %s as group %s, alerting to %s", RAW_LOGS_TOPIC, GROUP_ID, THREAT_ALERTS_TOPIC)

    try:
        while running:
            messages = consumer.consume(num_messages=BATCH_SIZE, timeout=POLL_TIMEOUT)
            if not messages:
                continue

            alerts = 0
            for msg in messages:
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error("Kafka error: %s", msg.error())
                    continue
                try:
                    payload = decode_message(msg)
                except ValueError:
                    continue

                event = parse_zscaler_line(payload.get("line"))
                if event is None or not is_threat(event):
                    continue

                produce_json(
                    THREAT_ALERTS_TOPIC,
                    {
                        **event,
                        "job_id": payload.get("job_id"),
                        "source": payload.get("source"),
                        "detected_at": payload.get("ingested_at"),
                    },
                    key=event["source_ip"],
                )
                alerts += 1

            # Make sure alerts are delivered before marking the input as consumed.
            if flush_producer() == 0:
                try:
                    consumer.commit(asynchronous=False)
                except KafkaException as e:
                    logger.warning("Offset commit failed: %s", e)
            else:
                logger.error("Some alerts were not delivered; offsets not committed")
            if alerts:
                logger.info("Published %d threat alerts", alerts)
    finally:
        flush_producer()
        consumer.close()
        logger.info("Stopped")


if __name__ == "__main__":
    main()
