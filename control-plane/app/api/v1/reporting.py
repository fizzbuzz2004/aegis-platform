import base64
import binascii
import io
import json
import re
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import assert_tenant_access, get_current_tenant_user
from app.models.orm import User, Tenant, ModuleResult

router = APIRouter()
MAX_LOGO_BYTES = 2 * 1024 * 1024
DEFAULT_BRAND_COLOR = "#0f766e"


def _brand_color(value: str | None):
    if value and re.fullmatch(r"#[0-9a-fA-F]{6}", value):
        return colors.HexColor(value)
    return colors.HexColor(DEFAULT_BRAND_COLOR)


def _logo_image(encoded_logo: str | None):
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
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    return start, end


@router.get("/reports/tenant/{tenant_id}/monthly-pdf")
def generate_monthly_compliance_report(
    tenant_id: int,
    current_user: User = Depends(get_current_tenant_user),
    db: Session = Depends(get_db),
):
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mandant nicht gefunden")
    assert_tenant_access(current_user, tenant.id)

    now = datetime.now(timezone.utc)
    month_start, month_end = _month_bounds(now)
    results = (
        db.query(ModuleResult)
        .filter(
            ModuleResult.tenant_id == tenant.id,
            ModuleResult.timestamp >= month_start,
            ModuleResult.timestamp < month_end,
        )
        .order_by(ModuleResult.timestamp.desc())
        .all()
    )

    latest_by_host_module = {}
    for result in results:
        latest_by_host_module.setdefault((result.hostname, result.module_name), result)

    parsed_findings = {}
    evaluated = 0
    passed = 0
    for key, result in latest_by_host_module.items():
        try:
            findings = json.loads(result.findings)
            if not isinstance(findings, list):
                findings = []
        except (TypeError, json.JSONDecodeError):
            findings = []
        parsed_findings[key] = findings
        for finding in findings:
            finding_status = str(finding.get("status", "")).upper()
            if finding_status in {"PASS", "FAIL"}:
                evaluated += 1
                passed += finding_status == "PASS"

    score = round(100 * passed / evaluated) if evaluated else None
    brand = _brand_color(tenant.brand_color_hex)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=colors.HexColor("#17212b"), alignment=TA_RIGHT, spaceAfter=4))
    styles.add(ParagraphStyle(name="ReportMeta", parent=styles["Normal"], fontSize=9, leading=13, textColor=colors.HexColor("#51606b"), alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="SectionTitle", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=brand, spaceBefore=12, spaceAfter=6))
    styles.add(ParagraphStyle(name="SmallBody", parent=styles["BodyText"], fontSize=8, leading=11, textColor=colors.HexColor("#263238")))
    styles.add(ParagraphStyle(name="SmallMuted", parent=styles["BodyText"], fontSize=8, leading=11, textColor=colors.HexColor("#64727c")))

    buffer = io.BytesIO()

    def draw_page(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(brand)
        canvas.setLineWidth(1.2)
        canvas.line(18 * mm, 16 * mm, A4[0] - 18 * mm, 16 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64727c"))
        footer = tenant.custom_footer or "Vertraulich | Technischer Audit-Bericht, keine rechtliche Zertifizierung"
        canvas.drawString(18 * mm, 11 * mm, footer[:150])
        canvas.drawRightString(A4[0] - 18 * mm, 11 * mm, f"Seite {document.page}")
        canvas.restoreState()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=23 * mm,
        title=f"Compliance Audit - {tenant.name}",
        author=tenant.name,
    )
    logo = _logo_image(tenant.logo_base64)
    brand_name = escape(tenant.name)
    title_cell = [
        Paragraph("EXECUTIVE COMPLIANCE AUDIT", styles["ReportTitle"]),
        Paragraph(f"{brand_name} | {now.strftime('%d.%m.%Y')} | {now.strftime('%m/%Y')}", styles["ReportMeta"]),
    ]
    header = Table([[logo or Paragraph(brand_name, styles["Heading2"]), title_cell]], colWidths=[48 * mm, 126 * mm])
    header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LINEBELOW", (0, 0), (-1, -1), 1.5, brand),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))

    story = [header, Spacer(1, 8 * mm)]
    story.append(Paragraph("Management Summary", styles["SectionTitle"]))
    story.append(Paragraph(
        "Dieser Bericht fasst die im Berichtsmonat eingegangenen technischen Agent-Prüfungen "
        "zusammen und ordnet die Findings den gemeldeten NIS2-Art.-21- und ISO/IEC-27001-Kontrollen "
        "zu. Er ist ein technischer Nachweis und ersetzt keine rechtliche Bewertung oder Zertifizierung.",
        styles["BodyText"],
    ))
    score_text = f"{score}%" if score is not None else "Keine bewertbaren Prüfungen"
    score_table = Table([
        [Paragraph("COMPLIANCE-SCORE", styles["SmallMuted"]), Paragraph("BEWERTETE KONTROLLEN", styles["SmallMuted"]), Paragraph("HOSTS MIT AUDIT", styles["SmallMuted"])],
        [Paragraph(f"<b>{score_text}</b>", styles["Heading2"]), Paragraph(f"<b>{evaluated}</b>", styles["Heading2"]), Paragraph(f"<b>{len({host for host, _ in latest_by_host_module})}</b>", styles["Heading2"])],
    ], colWidths=[58 * mm, 58 * mm, 58 * mm])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f4")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5dfdc")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dfdc")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([Spacer(1, 5 * mm), score_table, Paragraph("Prüfergebnisse je Host", styles["SectionTitle"])])

    hosts = sorted({host for host, _ in latest_by_host_module})
    if not hosts:
        story.append(Paragraph("Für diesen Monat liegen keine Agent-Prüfergebnisse vor.", styles["SmallMuted"]))

    for hostname in hosts:
        story.append(Paragraph(escape(hostname), styles["Heading3"]))
        rows = [["Modul", "Prüfung", "Status", "Schweregrad", "Kontrollreferenz"]]
        for (result_host, module_name), result in sorted(latest_by_host_module.items()):
            if result_host != hostname:
                continue
            findings = parsed_findings[(result_host, module_name)]
            if not findings:
                rows.append([module_name, "Keine Findings gemeldet", "INFO", "-", "-"])
            for finding in findings:
                refs = ", ".join(str(ref) for ref in finding.get("compliance", []) or []) or "-"
                rows.append([
                    Paragraph(escape(str(module_name)), styles["SmallBody"]),
                    Paragraph(escape(str(finding.get("code", "Audit"))) + "<br/>" + escape(str(finding.get("message", ""))), styles["SmallBody"]),
                    Paragraph(escape(str(finding.get("status", "UNKNOWN"))), styles["SmallBody"]),
                    Paragraph(escape(str(finding.get("severity", "-"))), styles["SmallBody"]),
                    Paragraph(escape(refs), styles["SmallBody"]),
                ])
        table = Table(rows, colWidths=[27 * mm, 61 * mm, 20 * mm, 23 * mm, 43 * mm], repeatRows=1, splitByRow=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), brand),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 7),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d5dfdc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.extend([table, Spacer(1, 4 * mm)])

    report_id = f"AEGIS-{tenant.id}-{now.strftime('%Y%m%d%H%M%S')}"
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(f"Berichts-ID: {report_id} | Berichtszeitraum: {month_start.strftime('%m/%Y')}", styles["SmallMuted"]))
    document.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    buffer.seek(0)

    safe_tenant_name = re.sub(r"[^A-Za-z0-9_-]+", "_", tenant.name).strip("_") or "tenant"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="NIS2_Report_{safe_tenant_name}.pdf"'},
    )
