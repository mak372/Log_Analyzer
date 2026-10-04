import os
import json
import logging
from datetime import datetime, timezone

from confluent_kafka import Producer, Consumer, KafkaException
from confluent_kafka.admin import AdminClient, NewTopic

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

RAW_LOGS_TOPIC = os.getenv("KAFKA_RAW_LOGS_TOPIC", "zscaler.logs.raw")
THREAT_ALERTS_TOPIC = os.getenv("KAFKA_THREAT_ALERTS_TOPIC", "threat.alerts")
TOPIC_PARTITIONS = int(os.getenv("KAFKA_TOPIC_PARTITIONS", "3"))

_producer = None


def ensure_topics():
    """Create the topics if they don't exist yet. Safe to call on every startup."""
    admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS})
    existing = admin.list_topics(timeout=10).topics
    missing = [
        NewTopic(name, num_partitions=TOPIC_PARTITIONS, replication_factor=1)
        for name in (RAW_LOGS_TOPIC, THREAT_ALERTS_TOPIC)
        if name not in existing
    ]
    if not missing:
        return
    for name, future in admin.create_topics(missing).items():
        try:
            future.result()
            logger.info("Created Kafka topic %s", name)
        except KafkaException as e:
            # Another process may have created it in the meantime.
            if "TOPIC_ALREADY_EXISTS" not in str(e):
                raise


def get_producer():
    global _producer
    if _producer is None:
        _producer = Producer({
            "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
            "acks": "all",
            "enable.idempotence": True,
            "linger.ms": 20,
            "compression.type": "lz4",
        })
    return _producer


def produce_json(topic, value, key=None, on_delivery=None):
    """Queue a JSON message. Polls the producer so delivery callbacks fire and the local queue drains."""
    producer = get_producer()
    payload = json.dumps(value, default=str).encode("utf-8")
    while True:
        try:
            producer.produce(
                topic,
                value=payload,
                key=key.encode("utf-8") if key else None,
                on_delivery=on_delivery,
            )
            break
        except BufferError:
            # Local queue is full: wait for in-flight messages to be delivered, then retry.
            producer.poll(0.5)
    producer.poll(0)


def produce_raw_log(line, source, job_id=None, key=None, on_delivery=None):
    """Send one raw log line to the raw logs topic.

    `key` should be the event's source IP so all events from one host land on the same
    partition and stay in order.
    """
    produce_json(
        RAW_LOGS_TOPIC,
        {
            "line": line,
            "source": source,
            "job_id": job_id,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
        },
        key=key,
        on_delivery=on_delivery,
    )


def flush_producer(timeout=30):
    """Block until all queued messages are delivered. Returns the number still undelivered."""
    return get_producer().flush(timeout)


def create_consumer(group_id, auto_offset_reset="earliest", **overrides):
    config = {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "group.id": group_id,
        "auto.offset.reset": auto_offset_reset,
        # Offsets are committed manually after work is done (at-least-once delivery).
        "enable.auto.commit": False,
    }
    config.update(overrides)
    return Consumer(config)


def decode_message(msg):
    return json.loads(msg.value().decode("utf-8"))
