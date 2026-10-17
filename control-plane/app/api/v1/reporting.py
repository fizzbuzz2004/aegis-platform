import base64
import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional
from xml.sax.saxutils import escape

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import assert_tenant_access, get_current_tenant_user
from app.models.orm import User, Tenant, ModuleResult, HostDevice

router = APIRouter()
MAX_LOGO_BYTES = 2 * 1024 * 1024
DEFAULT_BRAND_COLOR = "#0f766e"

# Thread-sicherer In-Memory Job-Store für asynchrone Report-Jobs (alternativ in DB abbildbar)
report_jobs_store: Dict[str, dict] = {}


class ReportJobResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    job_id: str
    status: str
    status_url: str
    download_url: Optional[str] = None


def _brand_color(value: str | None):
    """Validiert und konvertiert den Hex-Farbcode des Mandantenbranding."""
    if value and re.fullmatch(r"#[0-9a-fA-F]{6}", value):
        return colors.HexColor(value)
    return colors.HexColor(DEFAULT_BRAND_COLOR)


def _logo_image(encoded_logo: str | None):
    """Validiert und decodiert das Base64-Unternehmenslogo sicher."""
    if not encoded_logo:
        return None
    encoded_logo = encoded_logo.strip()
    if encoded_logo.startswith("data:"):
        _, separator, encoded_logo = encoded_logo.partition(",")
        if not separator:
            return None
    try:
        logo_bytes = base64.b64decode(encoded_logo, validate=True)
        if not logo_bytes or len(logo_bytes) > MAX_LOGO_BYTES:
            return None
        image_reader = ImageReader(io.BytesIO(logo_bytes))
        image_width, image_height = image_reader.getSize()
        if image_width <= 0 or image_height <= 0 or image_width * image_height > 4_000_000:
            return None
        image_reader.getRGBData()
        return Image(io.BytesIO(logo_bytes), width=42 * mm, height=20 * mm, kind="proportional")
    except Exception:
        return None


def _month_bounds(now: datetime) -> tuple[datetime, datetime]:
    """Berechnet die UTC-Monatsgrenzen für Monatsreports."""
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    return start, end


def _current_results(results: list[ModuleResult]) -> list[ModuleResult]:
    """Filtert die neuesten Testergebnisse je Host und Modul."""
    latest_by_host_module = {}
    for result in sorted(
        results,
        key=lambda item: item.timestamp.timestamp() if item.timestamp else float("-inf"),
        reverse=True,
    ):
        latest_by_host_module.setdefault((result.hostname, result.module_name), result)
    return list(latest_by_host_module.values())


def _decode_findings(result: ModuleResult) -> list[dict]:
    """Decodiert Findings aus dem JSON-Datenfeld sicher."""
    try:
        findings = json.loads(result.findings)
    except (TypeError, json.JSONDecodeError):
        return []
    return [finding for finding in findings if isinstance(finding, dict)] if isinstance(findings, list) else []


def _draw_worm_verification_block(story, tenant_id: int, results: list[ModuleResult], styles):
    """Integriert den kryptografischen WORM-Head-Hash und einen Verifikations-QR-Code in den PDF-Report."""
    worm_results = [r for r in results if r.module_name == "worm_audit"]
    head_hash = "NICHT VERFÜGBAR (Kein Audit-Block)"
    
    if worm_results:
        latest_worm = max(worm_results, key=lambda item: item.timestamp.timestamp() if item.timestamp else float("-inf"))
        try:
            findings = json.loads(latest_worm.findings)
            for f in findings:
                if "Head-Hash:" in f.get("message", ""):
                    head_hash = f.get("message").split("Head-Hash:")[-1].strip()
        except Exception:
            pass

    story.append(Paragraph("Kryptografischer WORM-Integritätsnachweis (Audit-Chain)", styles["AegisSection"]))
    story.append(Paragraph(
        f"<b>Aktueller Chain Head-Hash (SHA-256 HMAC):</b><br/><font name='Courier' size=7>{escape(head_hash)}</font>",
        styles["AegisSmall"]
    ))

    verify_url = f"https://aegis.control-plane.internal/api/v1/audit/verify?tenant_id={tenant_id}&hash={head_hash}"
    qr_widget = QrCodeWidget(verify_url)
    qr_widget.barWidth = 50 * mm
    qr_widget.barHeight = 50 * mm
    qr_widget.errorCorrectionLevel = 2

    d = Drawing(50 * mm, 50 * mm)
    d.add(qr_widget)

    qr_table = Table([[d, Paragraph(
        "<b>Auditor-Prüfhinweis:</b><br/>"
        "Scannen Sie diesen QR-Code oder nutzen Sie den API-Deep-Link, "
        "um die vollständige kryptografische Integritätskette direkt gegen die WORM-Datenbank "
        "der Control Plane zu verifizieren (NIS2 Art. 21.2.j / ISO 27001 A.8.15).",
        styles["AegisSmall"],
    )]], colWidths=[55 * mm, 120 * mm])
    
    qr_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([Spacer(1, 3 * mm), qr_table, Spacer(1, 4 * mm)])


def _pdf_report(tenant: Tenant, hosts: list[HostDevice], results: list[ModuleResult], host_scope: str | None = None):
    """Generiert den vollständigen PDF-Compliance-Bericht mit ReportLab."""
    now = datetime.now(timezone.utc)
    brand = _brand_color(tenant.brand_color_hex)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="AegisTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=colors.HexColor("#17212b"), alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="AegisMeta", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#52616b"), alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="AegisSection", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=brand, spaceBefore=10, spaceAfter=5, keepWithNext=True))
    styles.add(ParagraphStyle(name="AegisBody", parent=styles["BodyText"], fontSize=8, leading=11, textColor=colors.HexColor("#263238")))
    styles.add(ParagraphStyle(name="AegisSmall", parent=styles["BodyText"], fontSize=7, leading=9, textColor=colors.HexColor("#263238")))
    styles.add(ParagraphStyle(name="AegisMuted", parent=styles["BodyText"], fontSize=8, leading=11, textColor=colors.HexColor("#64727c")))
    
    story = []
    buffer = io.BytesIO()
    safe_tenant = escape(tenant.name)
    report_scope = f"Host: {escape(host_scope)}" if host_scope else "Mandantenübersicht"
    logo = _logo_image(tenant.logo_base64)
    
    title_block = [
        Paragraph("COMPLIANCE- & SICHERHEITSBERICHT", styles["AegisTitle"]),
        Paragraph(f"{safe_tenant} | {report_scope} | {now.strftime('%d.%m.%Y %H:%M UTC')}", styles["AegisMeta"]),
    ]
    header = Table([[logo or Paragraph(safe_tenant, styles["Heading2"]), title_block]], colWidths=[48 * mm, 126 * mm])
    header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LINEBELOW", (0, 0), (-1, -1), 1.5, brand),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    story.extend([header, Spacer(1, 5 * mm)])

    current_res = _current_results(results)
    results_by_host: dict[str, list[ModuleResult]] = {}
    for result in current_res:
        results_by_host.setdefault(result.hostname, []).append(result)
    if host_scope:
        hosts = [host for host in hosts if host.hostname == host_scope]
    host_names = sorted({host.hostname for host in hosts} | set(results_by_host))
    result_findings = {
        (result.hostname, result.module_name): _decode_findings(result)
        for result in current_res
    }
    evaluated = passed = 0
    for findings in result_findings.values():
        for finding in findings:
            finding_status = str(finding.get("status", "")).upper()
            if finding_status in {"PASS", "FAIL"}:
                evaluated += 1
                passed += finding_status == "PASS"
                
    score = round(100 * passed / evaluated) if evaluated else None
    score_text = f"{score}%" if score is not None else "Keine bewertbaren Prüfungen"
    host_summary_rows = [["Host", "Betriebssystem", "Score", "Letzter Check-in", "Prüfungen"]]
    known_hosts = {host.hostname: host for host in hosts}
    
    for hostname in host_names:
        host_results = results_by_host.get(hostname, [])
        host_checks = [
            finding for result in host_results
            for finding in result_findings[(result.hostname, result.module_name)]
            if str(finding.get("status", "")).upper() in {"PASS", "FAIL"}
        ]
        host_passed = sum(str(finding.get("status", "")).upper() == "PASS" for finding in host_checks)
        host_score = f"{round(100 * host_passed / len(host_checks))}%" if host_checks else "—"
        latest_result = max(
            (result for result in host_results if result.timestamp),
            key=lambda result: result.timestamp.timestamp(),
            default=None,
        )
        latest = latest_result.timestamp if latest_result else None
        os_info = known_hosts[hostname].os_info if hostname in known_hosts else "Unbekannt"
        host_summary_rows.append([
            Paragraph(escape(hostname), styles["AegisSmall"]),
            Paragraph(escape(os_info), styles["AegisSmall"]),
            host_score,
            latest.strftime("%Y-%m-%d %H:%M UTC") if latest else "Keine Daten",
            str(len(host_checks)),
        ])

    story.append(Paragraph("Management-Zusammenfassung", styles["AegisSection"]))
    story.append(Paragraph(
        "Dieser Bericht fasst die zuletzt gespeicherten Agent-Prüfergebnisse zusammen. "
        "Scores bewerten ausschließlich Findings mit Status PASS oder FAIL; WARN/INFO werden "
        "separat als Nachweise aufgeführt.",
        styles["AegisBody"],
    ))
    metrics = Table([
        ["COMPLIANCE-SCORE", "BEWERTETE CHECKS", "HOSTS"],
        [score_text, str(evaluated), str(len(host_names))],
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
    story.extend([Spacer(1, 3 * mm), metrics, Paragraph("Host-Übersicht", styles["AegisSection"])])
    
    host_table = Table(host_summary_rows, colWidths=[39 * mm, 38 * mm, 20 * mm, 48 * mm, 29 * mm], repeatRows=1, splitByRow=1)
    host_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), brand),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d5dfdc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(host_table)

    story.append(Paragraph("Audit-Evidence & Findings", styles["AegisSection"]))
    if not current_res:
        story.append(Paragraph("Für diesen Scope liegen noch keine Agent-Prüfergebnisse vor.", styles["AegisMuted"]))
        
    for hostname in host_names:
        host_results = sorted(results_by_host.get(hostname, []), key=lambda item: item.module_name)
        if not host_results:
            continue
        story.append(Paragraph(f"{escape(hostname)} — {escape(known_hosts[hostname].os_info if hostname in known_hosts else 'Host nicht registriert')}", styles["Heading3"]))
        rows = [["Modul", "Finding / Nachweis", "Status", "Severity", "Framework-Referenzen"]]
        for result in host_results:
            findings = result_findings[(result.hostname, result.module_name)]
            if not findings:
                rows.append([
                    Paragraph(escape(result.module_name), styles["AegisSmall"]),
                    Paragraph("Keine Findings gemeldet", styles["AegisSmall"]),
                    "INFO", "—", "—",
                ])
            for finding in findings:
                references = finding.get("compliance", [])
                if not isinstance(references, list):
                    references = []
                rows.append([
                    Paragraph(escape(result.module_name), styles["AegisSmall"]),
                    Paragraph(
                        f"<b>{escape(str(finding.get('code', 'Audit')))}</b><br/>{escape(str(finding.get('message', '')))}",
                        styles["AegisSmall"],
                    ),
                    Paragraph(escape(str(finding.get("status", "UNKNOWN"))), styles["AegisSmall"]),
                    Paragraph(escape(str(finding.get("severity", "—"))), styles["AegisSmall"]),
                    Paragraph(escape(", ".join(str(ref) for ref in references) or "—"), styles["AegisSmall"]),
                ])
        findings_table = Table(rows, colWidths=[25 * mm, 67 * mm, 18 * mm, 23 * mm, 41 * mm], repeatRows=1, splitByRow=1)
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
        story.extend([Paragraph(f"{escape(hostname)} – Findings", styles["Heading3"]), findings_table, Spacer(1, 2 * mm)])

    _draw_worm_verification_block(story, tenant.id, current_res, styles)

    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        f"Berichts-ID: AEGIS-{tenant.id}-{now.strftime('%Y%m%d%H%M%S')} | "
        f"Erstellt: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        styles["AegisMuted"],
    ))

    def draw_page(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(brand)
        canvas.setLineWidth(1)
        if logo:
            canvas.saveState()
            canvas.translate(18 * mm, A4[1] - 15 * mm)
            canvas.scale(0.5, 0.5)
            logo.drawOn(canvas, 0, 0)
            canvas.restoreState()
            tenant_name_x = 42 * mm
        else:
            tenant_name_x = 18 * mm
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(brand)
        canvas.drawString(tenant_name_x, A4[1] - 10 * mm, tenant.name[:48])
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(A4[0] - 18 * mm, A4[1] - 10 * mm, "Compliance- & Sicherheitsbericht")
        canvas.line(18 * mm, A4[1] - 14 * mm, A4[0] - 18 * mm, A4[1] - 14 * mm)
        canvas.line(18 * mm, 16 * mm, A4[0] - 18 * mm, 16 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64727c"))
        footer = tenant.custom_footer or "Vertraulich | Technischer Audit-Bericht"
        canvas.drawString(18 * mm, 11 * mm, footer[:145])
        canvas.drawRightString(A4[0] - 18 * mm, 11 * mm, f"Seite {document.page}")
        canvas.restoreState()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Compliance Report - {tenant.name}",
        author=tenant.name,
    )
    document.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    buffer.seek(0)
    return buffer.getvalue()


def _background_generate_report(job_id: str, tenant: Tenant, hosts: list[HostDevice], results: list[ModuleResult], host_scope: str | None = None):
    """Führt die PDF-Generierung im Hintergrund aus, um den Web-Worker zu entlasten."""
    try:
        report_jobs_store[job_id]["status"] = "running"
        pdf_bytes = _pdf_report(tenant, hosts, results, host_scope)
        report_jobs_store[job_id]["pdf_bytes"] = pdf_bytes
        report_jobs_store[job_id]["status"] = "complete"
    except Exception as e:
        report_jobs_store[job_id]["status"] = "failed"
        report_jobs_store[job_id]["error"] = str(e)


@router.post("/reports/tenant/{tenant_id}/pdf", response_model=ReportJobResponseSchema, status_code=status.HTTP_202_ACCEPTED)
def submit_tenant_compliance_report(
    tenant_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_tenant_user),
    db: Session = Depends(get_db),
):
    """Nimmt den Auftrag zur Mandanten-Compliance-Report-Generierung asynchron an."""
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mandant nicht gefunden")
    assert_tenant_access(current_user, tenant.id)
    hosts = db.query(HostDevice).filter(HostDevice.tenant_id == tenant.id).all()
    results = db.query(ModuleResult).filter(ModuleResult.tenant_id == tenant.id).order_by(ModuleResult.timestamp.desc()).all()

    job_id = str(uuid.uuid4())
    report_jobs_store[job_id] = {"status": "queued", "filename": f"Compliance_Report_{tenant.name}_A4.pdf"}

    background_tasks.add_task(_background_generate_report, job_id, tenant, hosts, results, None)

    return ReportJobResponseSchema(
        job_id=job_id,
        status="queued",
        status_url=f"/api/v1/reports/jobs/{job_id}",
    )


@router.post("/reports/tenant/{tenant_id}/host/{hostname}/pdf", response_model=ReportJobResponseSchema, status_code=status.HTTP_202_ACCEPTED)
def submit_host_compliance_report(
    tenant_id: int,
    hostname: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_tenant_user),
    db: Session = Depends(get_db),
):
    """Nimmt den Auftrag zur Host-Compliance-Report-Generierung asynchron an."""
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mandant nicht gefunden")
    assert_tenant_access(current_user, tenant.id)
    hosts = db.query(HostDevice).filter(
        HostDevice.tenant_id == tenant.id,
        HostDevice.hostname == hostname,
    ).all()
    results = db.query(ModuleResult).filter(
        ModuleResult.tenant_id == tenant.id,
        ModuleResult.hostname == hostname,
    ).order_by(ModuleResult.timestamp.desc()).all()
    if not hosts and not results:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host nicht gefunden")

    safe_host = re.sub(r"[^A-Za-z0-9_-]+", "_", hostname).strip("_") or "host"
    job_id = str(uuid.uuid4())
    report_jobs_store[job_id] = {"status": "queued", "filename": f"Compliance_Report_{tenant.name}_{safe_host}_A4.pdf"}

    background_tasks.add_task(_background_generate_report, job_id, tenant, hosts, results, hostname)

    return ReportJobResponseSchema(
        job_id=job_id,
        status="queued",
        status_url=f"/api/v1/reports/jobs/{job_id}",
    )


@router.get("/reports/jobs/{job_id}", response_model=ReportJobResponseSchema)
def get_report_job_status(job_id: str):
    """Prüft den Status eines asynchronen Report-Jobs und liefert bei Fertigstellung den Download-Link."""
    job = report_jobs_store.get(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report job not found")
    
    download_url = f"/api/v1/reports/jobs/{job_id}/download" if job["status"] == "complete" else None
    return ReportJobResponseSchema(
        job_id=job_id,
        status=job["status"],
        status_url=f"/api/v1/reports/jobs/{job_id}",
        download_url=download_url,
    )


@router.get("/reports/jobs/{job_id}/download")
def download_report_job(job_id: str):
    """Lädt das fertig generierte PDF des Report-Jobs herunter."""
    job = report_jobs_store.get(job_id)
    if not job or job["status"] != "complete" or "pdf_bytes" not in job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not ready or not found")
    
    filename = job.get("filename", "Compliance_Report_A4.pdf")
    safe_filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", filename).strip("._") or "Compliance_Report_A4.pdf"
    
    return Response(
        content=job["pdf_bytes"],
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
    )
