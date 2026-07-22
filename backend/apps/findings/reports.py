"""
Findings export: CSV, JSON, and PDF. Pure generation functions --
each takes a queryset/list of Finding objects and returns bytes, no
HTTP concerns here (that's the view's job, see apps/api/views.py's
export action). Keeping these as plain functions makes them directly
unit-testable without spinning up a request.
"""

import csv
import io
import json

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

CSV_COLUMNS = [
    "title", "severity", "finding_type", "asset_value",
    "is_active", "first_seen", "last_seen", "description",
]


def generate_csv(findings) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for f in findings:
        writer.writerow({
            "title": f.title,
            "severity": f.severity,
            "finding_type": f.finding_type,
            "asset_value": f.asset.value,
            "is_active": f.is_active,
            "first_seen": f.first_seen.isoformat(),
            "last_seen": f.last_seen.isoformat(),
            "description": f.description,
        })
    return buffer.getvalue().encode("utf-8")


def generate_json(findings) -> bytes:
    payload = [
        {
            "title": f.title,
            "severity": f.severity,
            "finding_type": f.finding_type,
            "asset_value": f.asset.value,
            "is_active": f.is_active,
            "first_seen": f.first_seen.isoformat(),
            "last_seen": f.last_seen.isoformat(),
            "description": f.description,
            "raw_data": f.raw_data,
        }
        for f in findings
    ]
    return json.dumps(payload, indent=2).encode("utf-8")


# Severity -> row background tint, so a scanned page is immediately
# skimmable by risk level without reading every cell.
SEVERITY_COLORS = {
    "critical": colors.HexColor("#fde2e2"),
    "high": colors.HexColor("#fde8d0"),
    "medium": colors.HexColor("#fdf6d0"),
    "low": colors.HexColor("#e8f4fd"),
    "info": colors.white,
}


def generate_pdf(findings, organization_name: str) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.5 * inch, bottomMargin=0.5 * inch,
        leftMargin=0.5 * inch, rightMargin=0.5 * inch,
    )
    styles = getSampleStyleSheet()
    elements = [
        Paragraph(f"Security Findings Report: {organization_name}", styles["Title"]),
        Spacer(1, 0.1 * inch),
        Paragraph(f"{len(findings)} finding(s)", styles["Normal"]),
        Spacer(1, 0.25 * inch),
    ]

    table_data = [["Severity", "Title", "Asset", "Type", "Status", "First Seen"]]
    row_colors = [colors.HexColor("#374151")]  # header row color, index 0

    for f in findings:
        table_data.append([
            f.severity.upper(),
            Paragraph(f.title, styles["BodyText"]),
            f.asset.value,
            f.finding_type,
            "Active" if f.is_active else "Resolved",
            f.first_seen.strftime("%Y-%m-%d"),
        ])
        row_colors.append(SEVERITY_COLORS.get(f.severity, colors.white))

    table = Table(table_data, repeatRows=1, colWidths=[0.7*inch, 2.3*inch, 1.3*inch, 1.1*inch, 0.7*inch, 0.9*inch])

    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, color in enumerate(row_colors[1:], start=1):
        style_commands.append(("BACKGROUND", (0, i), (0, i), color))

    table.setStyle(TableStyle(style_commands))
    elements.append(table)

    doc.build(elements)
    return buffer.getvalue()