# control-plane/app/services/outbox_worker.py
import asyncio
import logging
import random
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from app.core.database import SessionLocal
from app.models.v2 import OutboxEvent
from app.services.webhook import dispatch_webhook

logger = logging.getLogger(__name__)

async def process_outbox_queue():
    while True:
        db = SessionLocal()
        try:
            now = datetime.now(timezone.utc)
            events = db.scalars(
                select(OutboxEvent)
                .where(OutboxEvent.published_at.is_(None), OutboxEvent.available_at <= now)
                .order_by(OutboxEvent.created_at)
                .limit(50)
            ).all()

            for event in events:
                try:
                    # Zustellung an konfigurierte Webhooks
                    dispatch_webhook(event.payload.get("url"), event.payload.get("secret_token"), event.payload)
                    event.published_at = datetime.now(timezone.utc)
                    event.attempts += 1
                    db.commit()
                except Exception as e:
                    event.attempts += 1
                    # Exponentieller Backoff mit Jitter (Basis 2, max. 15 Minuten = 900 Sekunden)
                    backoff = min(900, 2 ** event.attempts)
                    jitter = random.uniform(0, 1)
                    delay = backoff + jitter
                    event.available_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
                    db.commit()
                    logger.warning(f"Outbox Event {event.id} Zustellung fehlgeschlagen (Versuch {event.attempts}, nächster Versuch in {delay:.1f}s): {e}")
        except Exception as ex:
            logger.error(f"Outbox Worker Fehler: {ex}")
        finally:
            db.close()
        await asyncio.sleep(10)
