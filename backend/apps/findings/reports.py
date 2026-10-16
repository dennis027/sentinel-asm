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

from .guidance import guidance_for

CSV_COLUMNS = [
    "title", "severity", "finding_type", "asset_value",
    "is_active", "status", "first_seen", "last_seen", "description",
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
            "status": f.status,
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
            "status": f.status,
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


GRADE_MEANING = {
    "A+": "Little exposure found",
    "A": "Little exposure found",
    "B": "Some issues to review",
    "C": "Needs attention",
    "D": "Serious exposure",
    "F": "Serious exposure",
}


def generate_executive_report(
    organization, summary: dict, changes: dict, top_issues, narrative: list[str] | None = None,
    remediation: dict | None = None,
) -> bytes:
    """
    Two or three pages for someone who will never open the app: where
    the organization stands, what moved since last time, and the
    handful of things most worth fixing -- each with why it matters
    and what to do, not just a scanner's title.

    `summary` and `changes` come from apps.findings.summary, the same
    functions behind the dashboard, so the report and the screen agree.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter, title=f"Attack surface report: {organization.name}",
        topMargin=0.7 * inch, bottomMargin=0.7 * inch, leftMargin=0.8 * inch, rightMargin=0.8 * inch,
    )
    styles = getSampleStyleSheet()
    body, heading, small = styles["BodyText"], styles["Heading2"], styles["Italic"]
    story = [
        Paragraph(f"Attack surface report: {organization.name}", styles["Title"]),
        Paragraph(
            f"{organization.root_domain} &middot; generated {_today()}", styles["Normal"],
        ),
        Spacer(1, 0.25 * inch),
    ]

    # ---- in short ----
    if narrative:
        story.append(Paragraph("In short", heading))
        story.append(Paragraph(_escape(" ".join(narrative)), body))
        story.append(Spacer(1, 0.2 * inch))

    # ---- where we stand ----
    grade = summary["average_risk_grade"]
    severity = summary["active_findings_by_severity"]
    open_total = sum(severity.values())
    story.append(Paragraph("Where we stand", heading))
    if grade is None:
        story.append(Paragraph("No assets have been discovered yet, so there is nothing to grade.", body))
    else:
        story.append(Paragraph(
            f"<b>Risk grade {grade}</b> ({summary['average_risk_score']} out of 100) &mdash; "
            f"{GRADE_MEANING.get(grade, '')}.", body,
        ))
    story.append(Paragraph(
        f"{summary['asset_count']:,} internet-facing asset(s) are being monitored. "
        f"{summary['assets_at_risk']:,} of them have open issues, {open_total:,} in total: "
        f"{severity.get('critical', 0)} critical, {severity.get('high', 0)} high, "
        f"{severity.get('medium', 0)} medium, {severity.get('low', 0)} low, {severity.get('info', 0)} informational.",
        body,
    ))
    story.append(Spacer(1, 0.2 * inch))

    # ---- what changed ----
    story.append(Paragraph(f"What changed in the last {changes['days']} days", heading))
    change_table = Table(
        [
            ["New assets", "New issues", "Issues resolved"],
            [
                f"{changes['new_assets']['count']:,}",
                f"{changes['new_issues']['count']:,}",
                f"{changes['resolved_issues']['count']:,}",
            ],
        ],
        colWidths=[2.2 * inch] * 3,
    )
    change_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f3f6")),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, 1), 18),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 12),
        ("TOPPADDING", (0, 1), (-1, 1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cfd4dc")),
    ]))
    story.append(change_table)
    for label, key in (("New", "new_issues"), ("Resolved", "resolved_issues")):
        for item in changes[key]["items"]:
            story.append(Paragraph(
                f"{label}: [{item['severity'].upper()}] {_escape(item['title'])} "
                f"<font color='#5b6472'>({_escape(item['asset_value'])})</font>", body,
            ))
    story.append(Spacer(1, 0.2 * inch))

    # ---- how fast issues get fixed ----
    if remediation:
        mean = remediation.get("mean_days_to_fix")
        story.append(Paragraph("Remediation", heading))
        story.append(Paragraph(
            f"{remediation['overdue']:,} open issue(s) are past their fix-by date. "
            f"{remediation['unassigned_critical_high']:,} critical or high issue(s) have nobody assigned. "
            + (f"Over the last 90 days issues were fixed in {mean:g} days on average." if mean is not None
               else "No issues have been fixed in the last 90 days."),
            body,
        ))
        sla = remediation.get("sla_days", {})
        if sla:
            story.append(Paragraph(
                "Fix-by targets: " + ", ".join(f"{severity} {days} days" for severity, days in sla.items()) + ".",
                small,
            ))
        story.append(Spacer(1, 0.2 * inch))

    # ---- what to fix first ----
    story.append(Paragraph("What to fix first", heading))
    if not top_issues:
        story.append(Paragraph("There are no open issues.", body))
    for number, finding in enumerate(top_issues, start=1):
        guidance = guidance_for(finding)
        story.append(Paragraph(
            f"<b>{number}. [{finding.severity.upper()}] {_escape(finding.title)}</b> "
            f"<font color='#5b6472'>&mdash; {_escape(finding.asset.value)}</font>", body,
        ))
        if guidance["impact"]:
            story.append(Paragraph(f"<i>Why it matters:</i> {_escape(guidance['impact'])}", body))
        if guidance["remediation"]:
            story.append(Paragraph(f"<i>What to do:</i> {_escape(guidance['remediation'])}", body))
        story.append(Spacer(1, 0.1 * inch))

    if summary["worst_assets"]:
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph("Assets needing the most attention", heading))
        for asset in summary["worst_assets"]:
            story.append(Paragraph(
                f"Grade {asset['risk_grade']} &mdash; {_escape(asset['value'])} "
                f"({asset['open_findings']} open)", body,
            ))

    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        "The grade is the average score of the assets that have open issues; assets with none "
        "do not raise it. Accepted risks and false positives are excluded.", small,
    ))

    doc.build(story)
    return buffer.getvalue()


def _today() -> str:
    from django.utils import timezone

    return timezone.now().strftime("%B %d, %Y")


def _escape(text: str) -> str:
    # reportlab Paragraphs parse a small HTML subset; scanner-supplied
    # titles must not be read as markup.
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
