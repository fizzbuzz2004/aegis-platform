# control-plane/app/services/outbox_worker.py
from __future__ import annotations

import asyncio
import io
import logging
import random
from datetime import datetime, timezone, timedelta
from uuid import UUID
from xml.sax.saxutils import escape

import boto3
from sqlalchemy import select
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.config import settings
from app.core.v2_database import VerifiedTenantContext, _session_factory, set_transaction_tenant_context
from app.models.v2 import Customer, OutboxEvent, ReportJob, ScanFinding, ScanRun
from app.services.webhook import dispatch_webhook

logger = logging.getLogger(__name__)


def generate_v2_report_pdf(customer_name: str, scan_run: ScanRun, findings: list[ScanFinding]) -> bytes:
    """Generiert einen professionellen A4 Compliance-PDF-Report für V2 Scan-Runs mittels ReportLab."""
    buffer = io.BytesIO()
    brand = colors.HexColor("#0f766e")
    styles = getSampleStyleSheet()
    
    styles.add(ParagraphStyle(name="AegisTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=colors.HexColor("#17212b"), alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="AegisMeta", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#52616b"), alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="AegisSection", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=brand, spaceBefore=10, spaceAfter=5, keepWithNext=True))
    styles.add(ParagraphStyle(name="AegisBody", parent=styles["BodyText"], fontSize=8, leading=11, textColor=colors.HexColor("#263238")))
    styles.add(ParagraphStyle(name="AegisSmall", parent=styles["BodyText"], fontSize=7, leading=9, textColor=colors.HexColor("#263238")))
    styles.add(ParagraphStyle(name="AegisMuted", parent=styles["BodyText"], fontSize=8, leading=11, textColor=colors.HexColor("#64727c")))

    story = []
    safe_customer = escape(customer_name)
    now = datetime.now(timezone.utc)

    title_block = [
        Paragraph("V2 COMPLIANCE- & SECURITY REPORT", styles["AegisTitle"]),
        Paragraph(f"{safe_customer} | Snapshot: {scan_run.id} | {now.strftime('%d.%m.%Y %H:%M UTC')}", styles["AegisMeta"]),
    ]
    header = Table([[Paragraph(safe_customer, styles["Heading2"]), title_block]], colWidths=[48 * mm, 126 * mm])
    header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LINEBELOW", (0, 0), (-1, -1), 1.5, brand),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    story.extend([header, Spacer(1, 5 * mm)])

    evaluated = len(findings)
    passed = sum(1 for f in findings if str(f.status).upper() == "PASS")
    score = round(100 * passed / evaluated) if evaluated else None
    score_text = f"{score}%" if score is not None else "Keine Prüfungen"

    story.append(Paragraph("Management-Zusammenfassung (V2 Engine)", styles["AegisSection"]))
    story.append(Paragraph(
        f"Regelwerk-Digest: <b>{escape(scan_run.rule_pack_digest)}</b><br/>"
        f"Evaluierungszeitpunkt: {scan_run.evaluated_at.strftime('%Y-%m-%d %H:%M UTC') if scan_run.evaluated_at else 'Unbekannt'}",
        styles["AegisBody"],
    ))

    metrics = Table([
        ["COMPLIANCE-SCORE", "BEWERTETE CHECKS", "STATUS"],
        [score_text, str(evaluated), str(scan_run.status).upper()],
    ], colWidths=[58 * mm, 58 * mm, 58 * mm])
    metrics.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f4")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#52616b")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5dfdc")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dfdc")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([Spacer(1, 3 * mm), metrics, Spacer(1, 4 * mm)])

    story.append(Paragraph("Scan Findings & Evidence", styles["AegisSection"]))
    rows = [["Regel-ID", "Status", "Schweregrad", "Erstellungszeitpunkt"]]
    for f in findings:
        rows.append([
            Paragraph(escape(f.rule_id), styles["AegisSmall"]),
            Paragraph(escape(f.status), styles["AegisSmall"]),
            Paragraph(escape(f.severity), styles["AegisSmall"]),
            Paragraph(f.created_at.strftime('%Y-%m-%d %H:%M') if f.created_at else '-', styles["AegisSmall"]),
        ])
    
    findings_table = Table(rows, colWidths=[70 * mm, 30 * mm, 34 * mm, 40 * mm], repeatRows=1, splitByRow=1)
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), brand),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d5dfdc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(findings_table)

    def draw_page(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(brand)
        canvas.setLineWidth(1)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(brand)
        canvas.drawString(18 * mm, A4[1] - 10 * mm, customer_name[:48])
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(A4[0] - 18 * mm, A4[1] - 10 * mm, "Aegis V2 Compliance Report")
        canvas.line(18 * mm, A4[1] - 14 * mm, A4[0] - 18 * mm, A4[1] - 14 * mm)
        canvas.line(18 * mm, 16 * mm, A4[0] - 18 * mm, 16 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64727c"))
        canvas.drawString(18 * mm, 11 * mm, "Vertraulich | Technischer V2 Audit-Bericht")
        canvas.drawRightString(A4[0] - 18 * mm, 11 * mm, f"Seite {document.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )
    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    buffer.seek(0)
    return buffer.getvalue()


async def process_outbox_queue():
    """Hintergrund-Worker zur asynchronen Verarbeitung von Outbox-Events (Report-Jobs & Webhooks)."""
    while True:
        try:
            session_maker = _session_factory()
            async with session_maker() as session:
                async with session.begin():
                    now = datetime.now(timezone.utc)
                    events = (await session.scalars(
                        select(OutboxEvent)
                        .where(OutboxEvent.published_at.is_(None), OutboxEvent.available_at <= now)
                        .order_by(OutboxEvent.created_at)
                        .limit(50)
                    )).all()

                    for event in events:
                        tenant_context = VerifiedTenantContext(
                            user_id=event.msp_id,
                            msp_id=event.msp_id,
                            customer_id=event.customer_id
                        )
                        await set_transaction_tenant_context(session, tenant_context)

                        if event.aggregate_type == "report_job" and event.event_type == "report.generate.requested":
                            job_id = UUID(event.payload.get("job_id"))
                            job = await session.get(ReportJob, job_id)
                            if not job:
                                event.published_at = datetime.now(timezone.utc)
                                event.attempts += 1
                                continue

                            job.status = "running"
                            await session.flush()

                            try:
                                snapshot = await session.scalar(
                                    select(ScanRun).where(
                                        ScanRun.id == job.snapshot_id,
                                        ScanRun.msp_id == job.msp_id,
                                        ScanRun.customer_id == job.customer_id,
                                    )
                                )
                                customer = await session.scalar(
                                    select(Customer).where(
                                        Customer.msp_id == job.msp_id,
                                        Customer.id == job.customer_id,
                                    )
                                )
                                findings = (await session.scalars(
                                    select(ScanFinding).where(
                                        ScanFinding.scan_run_id == job.snapshot_id,
                                        ScanFinding.msp_id == job.msp_id,
                                        ScanFinding.customer_id == job.customer_id,
                                    )
                                )).all()

                                customer_name = customer.name if customer else "Mandant"
                                pdf_bytes = generate_v2_report_pdf(customer_name, snapshot, findings)

                                if not settings.EVIDENCE_BUCKET:
                                    raise RuntimeError("EVIDENCE_BUCKET is not configured")

                                s3 = boto3.client("s3", region_name=settings.AWS_REGION)
                                object_key = f"reports/v2/{job.msp_id}/{job.customer_id}/{job.id}.pdf"
                                
                                await asyncio.to_thread(
                                    s3.put_object,
                                    Bucket=settings.EVIDENCE_BUCKET,
                                    Key=object_key,
                                    Body=pdf_bytes,
                                    ContentType="application/pdf",
                                )

                                job.status = "complete"
                                job.object_key = object_key
                                job.completed_at = datetime.now(timezone.utc)
                                event.published_at = datetime.now(timezone.utc)
                                event.attempts += 1
                                logger.info(f"Report-Job {job.id} erfolgreich generiert und nach S3 hochgeladen: {object_key}")
                            except Exception as ex:
                                job.status = "failed"
                                event.attempts += 1
                                backoff = min(900, 2 ** event.attempts)
                                jitter = random.uniform(0, 1)
                                event.available_at = datetime.now(timezone.utc) + timedelta(seconds=backoff + jitter)
                                logger.error(f"Report-Job {job.id} Generierung fehlgeschlagen (Versuch {event.attempts}): {ex}")
                        elif "url" in event.payload:
                            try:
                                dispatch_webhook(event.payload.get("url"), event.payload.get("secret_token"), event.payload)
                                event.published_at = datetime.now(timezone.utc)
                                event.attempts += 1
                            except Exception as e:
                                event.attempts += 1
                                backoff = min(900, 2 ** event.attempts)
                                jitter = random.uniform(0, 1)
                                event.available_at = datetime.now(timezone.utc) + timedelta(seconds=backoff + jitter)
                                logger.warning(f"Webhook Outbox Event {event.id} fehlgeschlagen: {e}")
                        else:
                            event.published_at = datetime.now(timezone.utc)
                            event.attempts += 1
        except Exception as ex:
            logger.error(f"Outbox Worker Fehler: {ex}")
        await asyncio.sleep(10)
