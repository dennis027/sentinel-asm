"""
The organization-level numbers: current risk, and what changed lately.
Shared by the API (dashboard) and the PDF report so the two can never
disagree. Everything is aggregated in SQL -- nothing loads a row per asset.
"""

from datetime import timedelta

from django.db.models import Case, Count, IntegerField, Q, Sum, Value, When
from django.utils import timezone

from apps.assets.models import Asset

from .models import Finding, RiskSnapshot
from .risk_scoring import (
    GRADE_CAPS,
    MINIMUM_SCORE,
    SEVERITY_DEDUCTIONS,
    STARTING_SCORE,
    apply_grade_cap,
    grade_for_score,
)

WORST_ASSETS_SHOWN = 5
CHANGES_SHOWN = 5


def _open_issues(organization):
    return Finding.objects.counts_toward_risk().filter(
        asset__organization=organization, asset__is_active=True
    )


def assets_at_risk(organization) -> list[dict]:
    """Every active asset with open issues, worst score first, with its counts."""
    deduction = Case(
        *[When(severity=severity, then=Value(points)) for severity, points in SEVERITY_DEDUCTIONS.items()],
        default=Value(0),
        output_field=IntegerField(),
    )
    rows = [
        {
            "id": row["asset_id"],
            "value": row["asset__value"],
            # Same rule as Asset.risk_score: an open critical or high issue caps it.
            "risk_score": int(apply_grade_cap(
                max(MINIMUM_SCORE, STARTING_SCORE - row["deduction"]), row["critical"] > 0, row["high"] > 0
            )),
            "open_findings": row["open_findings"],
            "critical_high": row["critical"] + row["high"],
        }
        for row in _open_issues(organization).values("asset_id", "asset__value").annotate(
            deduction=Sum(deduction),
            open_findings=Count("id"),
            critical=Count("id", filter=Q(severity=Finding.Severity.CRITICAL)),
            high=Count("id", filter=Q(severity=Finding.Severity.HIGH)),
        )
    ]
    for asset in rows:
        asset["risk_grade"] = grade_for_score(asset["risk_score"])
    rows.sort(key=lambda asset: (asset["risk_score"], asset["value"]))
    return rows


def build_risk_summary(organization) -> dict:
    """
    The grade is the average score of the assets that HAVE open issues
    -- averaging over every asset would let thousands of clean
    subdomains hide a handful of badly exposed ones (41,000 clean hosts
    and 25 high-severity findings must not come out as an A+).

    An average still lets many lightly-affected hosts outweigh one
    seriously exposed one, so the worst open issue also caps the grade:
    any open critical issue holds it at C or below, any open high issue
    at B or below. One exposed database is enough to be a C, however
    tidy everything else is.
    """
    asset_count = organization.assets.filter(is_active=True).count()
    open_issues = _open_issues(organization)
    at_risk = assets_at_risk(organization)

    grade_counts: dict[str, int] = {}
    for asset in at_risk:
        grade_counts[asset["risk_grade"]] = grade_counts.get(asset["risk_grade"], 0) + 1
    clean = asset_count - len(at_risk)
    if clean > 0:
        grade_counts["A+"] = grade_counts.get("A+", 0) + clean

    if at_risk:
        average_score = round(sum(a["risk_score"] for a in at_risk) / len(at_risk), 1)
    else:
        average_score = float(STARTING_SCORE) if asset_count else None

    severity_counts = dict(open_issues.values_list("severity").annotate(count=Count("id")))

    capped_by = None
    if average_score is not None:
        for severity in (Finding.Severity.CRITICAL, Finding.Severity.HIGH):
            if severity_counts.get(severity) and average_score > GRADE_CAPS[severity]:
                average_score = float(GRADE_CAPS[severity])
                capped_by = severity
                break

    return {
        "organization": organization.name,
        "asset_count": asset_count,
        "assets_at_risk": len(at_risk),
        "average_risk_score": average_score,
        "average_risk_grade": grade_for_score(round(average_score)) if average_score is not None else None,
        # "critical" or "high" when an open issue of that severity is what
        # holds the grade down; None when the average decides alone.
        "grade_capped_by": capped_by,
        "grade_distribution": grade_counts,
        "active_findings_by_severity": {
            severity: severity_counts.get(severity, 0) for severity in Finding.Severity.values
        },
        # The few assets most worth looking at first.
        "worst_assets": at_risk[:WORST_ASSETS_SHOWN],
    }


def build_changes(organization, days: int = 7) -> dict:
    """
    What is different from `days` ago: hosts that appeared, issues that
    appeared, and issues that went away. This is the point of running
    scans continuously -- a single scan is a snapshot; this is the
    difference between two of them.

    Only real issues are counted (not inventory like DNS records), and
    "new" issues are the ones still open: one that appeared and was
    fixed inside the window shows up under resolved, not both.
    """
    since = timezone.now() - timedelta(days=days)
    issues = Finding.objects.filter(asset__organization=organization).exclude(
        finding_type__in=Finding.INVENTORY_TYPES
    )

    new_assets = Asset.objects.filter(organization=organization, first_seen__gte=since)
    new_issues = issues.filter(first_seen__gte=since, is_active=True)
    resolved_issues = issues.filter(is_active=False, resolved_at__gte=since)

    def finding_rows(queryset):
        return [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "asset": finding.asset_id,
                "asset_value": finding.asset.value,
            }
            for finding in queryset.select_related("asset").by_severity()[:CHANGES_SHOWN]
        ]

    new_by_severity = dict(new_issues.values_list("severity").annotate(count=Count("id")))

    return {
        "days": days,
        "since": since,
        "new_assets": {
            "count": new_assets.count(),
            "items": [
                {"id": asset.id, "value": asset.value}
                for asset in new_assets.order_by("-first_seen")[:CHANGES_SHOWN]
            ],
        },
        "new_issues": {
            "count": new_issues.count(),
            "by_severity": {s: new_by_severity.get(s, 0) for s in Finding.Severity.values},
            "items": finding_rows(new_issues),
        },
        "resolved_issues": {
            "count": resolved_issues.count(),
            "items": finding_rows(resolved_issues),
        },
    }



def record_snapshot(organization, summary: dict) -> RiskSnapshot:
    """Stores today's numbers (overwriting earlier ones from today)."""
    severity = summary["active_findings_by_severity"]
    snapshot, _ = RiskSnapshot.objects.update_or_create(
        organization=organization,
        date=timezone.localdate(),
        defaults={
            "score": summary["average_risk_score"],
            "grade": summary["average_risk_grade"] or "",
            "asset_count": summary["asset_count"],
            "assets_at_risk": summary["assets_at_risk"],
            "open_issues": sum(severity.values()),
            "critical_high": severity.get("critical", 0) + severity.get("high", 0),
        },
    )
    return snapshot


def build_trend(organization, days: int = 30) -> list[dict]:
    since = timezone.localdate() - timedelta(days=days)
    return [
        {
            "date": snapshot.date,
            "score": snapshot.score,
            "grade": snapshot.grade,
            "open_issues": snapshot.open_issues,
            "critical_high": snapshot.critical_high,
            "asset_count": snapshot.asset_count,
        }
        for snapshot in organization.risk_snapshots.filter(date__gte=since).order_by("date")
    ]


def _plural(count: int, word: str, plural: str | None = None) -> str:
    return f"{count:,} {word if count == 1 else (plural or word + 's')}"


def build_narrative(organization, summary: dict, changes: dict, remediation: dict, trend: list[dict]) -> list[str]:
    """
    The dashboard's numbers as a few plain sentences, for a reader who
    doesn't want to interpret a dashboard. Deterministic -- built from
    the same figures shown beside it, nothing invented.
    """
    sentences = []
    assets, at_risk = summary["asset_count"], summary["assets_at_risk"]
    if not assets:
        return [f"No assets have been discovered for {organization.name} yet. Run Subdomain discovery to start."]

    if at_risk:
        sentences.append(
            f"{organization.name} has {_plural(assets, 'internet-facing asset')}; "
            f"{at_risk:,} of them {'has' if at_risk == 1 else 'have'} open issues."
        )
    else:
        sentences.append(f"{organization.name} has {_plural(assets, 'internet-facing asset')}, none with open issues.")

    grade, score = summary["average_risk_grade"], summary["average_risk_score"]
    worst = summary["worst_assets"][:1]
    if grade and at_risk:
        driver = f", driven most by {worst[0]['value']} (grade {worst[0]['risk_grade']})" if worst else ""
        sentences.append(f"Overall risk is graded {grade} ({score:g} out of 100){driver}.")
        if summary.get("grade_capped_by") == Finding.Severity.CRITICAL:
            sentences.append("An open critical issue holds the grade at C until it is fixed.")
        elif summary.get("grade_capped_by") == Finding.Severity.HIGH:
            sentences.append("Open high-severity issues hold the grade at B until they are fixed.")

    severity = summary["active_findings_by_severity"]
    urgent = severity.get("critical", 0) + severity.get("high", 0)
    if urgent:
        sentences.append(
            f"{_plural(urgent, 'issue')} {'is' if urgent == 1 else 'are'} critical or high and should be fixed first."
        )

    new_issues, fixed = changes["new_issues"]["count"], changes["resolved_issues"]["count"]
    new_assets = changes["new_assets"]["count"]
    if new_issues or fixed or new_assets:
        parts = []
        if new_assets:
            parts.append(f"{_plural(new_assets, 'new host')} appeared")
        if new_issues:
            parts.append(f"{_plural(new_issues, 'new issue')} {'was' if new_issues == 1 else 'were'} found")
        if fixed:
            parts.append(f"{fixed:,} {'was' if fixed == 1 else 'were'} resolved")
        listed = ", ".join(parts[:-1]) + (" and " if len(parts) > 1 else "") + parts[-1]
        sentences.append(f"In the last {changes['days']} days {listed}.")
    else:
        sentences.append(f"Nothing changed in the last {changes['days']} days.")

    if remediation["overdue"]:
        overdue = remediation["overdue"]
        sentences.append(
            f"{_plural(overdue, 'issue')} {'is' if overdue == 1 else 'are'} past "
            f"{'its' if overdue == 1 else 'their'} fix-by date."
        )
    if remediation["mean_days_to_fix"] is not None:
        sentences.append(f"Issues are fixed in {remediation['mean_days_to_fix']:g} days on average.")

    scored = [point for point in trend if point["score"] is not None]
    if len(scored) >= 2:
        delta = round(scored[-1]["score"] - scored[0]["score"], 1)
        span = (scored[-1]["date"] - scored[0]["date"]).days
        if abs(delta) >= 1 and span >= 1:
            direction = "improved" if delta > 0 else "worsened"
            sentences.append(f"The score has {direction} by {abs(delta):g} points over the last {span} days.")
    return sentences
