# control-plane/app/services/outbox_worker.py
import asyncio
import logging
from sqlalchemy import select
from datetime import datetime, timezone
from app.core.database import SessionLocal
from app.models.v2 import OutboxEvent
from app.services.webhook import dispatch_webhook

logger = logging.getLogger(__name__)

async def process_outbox_queue():
    while True:
        db = SessionLocal()
        try:
            events = db.scalars(
                select(OutboxEvent)
                .where(OutboxEvent.published_at.is_(None))
                .order_by(OutboxEvent.created_at)
                .limit(50)
            ).all()

            for event in events:
                try:
                    # Zustellung an konfigurierte Webhooks mit exponentiellem Backoff
                    dispatch_webhook(event.payload.get("url"), event.payload.get("secret_token"), event.payload)
                    event.published_at = datetime.now(timezone.utc)
                    db.commit()
                except Exception as e:
                    event.attempts += 1
                    db.commit()
                    logger.warning(f"Outbox Event {event.id} Zustellung fehlgeschlagen (Versuch {event.attempts}): {e}")
        except Exception as ex:
            logger.error(f"Outbox Worker Fehler: {ex}")
        finally:
            db.close()
        await asyncio.sleep(10)
