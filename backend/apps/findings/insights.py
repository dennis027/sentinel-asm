"""
Views of an organization's findings that answer a question directly:

- the fix plan: "what should we do first, and what does it get us?"
- the inventories: "what software / which services / which
  certificates do we have on the internet?"

Read-only and computed on request; nothing here is stored.
"""

from collections import defaultdict
from datetime import datetime

from django.utils import timezone

from apps.assets.models import Asset, Technology

from .guidance import guidance_for
from .kev import index as kev_index
from .models import Finding
from .remediation import is_overdue
from .risk_scoring import GRADE_CAPS, calculate_risk_score, grade_for_score

SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Finding.Severity.values)}
FIX_PLAN_ITEMS = 500


def _fix_key(finding) -> tuple[str, str]:
    """Findings with the same key are fixed by the same action."""
    raw = finding.raw_data or {}
    if finding.finding_type == Finding.FindingType.OPEN_PORT:
        return finding.finding_type, f"port:{raw.get('port', '')}"
    if finding.finding_type == Finding.FindingType.MISSING_HEADER:
        return finding.finding_type, f"header:{raw.get('header', '')}"
    if raw.get("check"):
        return finding.finding_type, f"check:{raw['check']}"
    if raw.get("template_id"):
        return finding.finding_type, f"template:{raw['template_id']}"
    if finding.finding_type == Finding.FindingType.EXPIRED_SSL:
        return finding.finding_type, "certificate"
    return finding.finding_type, f"title:{finding.title}"


# What to call a step that covers several different-looking findings,
# by the second part of its fix key. Phrased as the thing to do.
GROUP_ACTIONS = {
    "certificate": "Renew TLS certificates that have expired or expire soon",
    "check:end_of_life": "Upgrade software that no longer gets security fixes",
    "check:lookalike_mail": "Respond to lookalike domains that can send email",
    "check:lookalike_web": "Respond to lookalike domains",
    "check:takeover": "Remove DNS records that point at unclaimed services",
    "check:old_protocol": "Turn off TLS 1.0 and TLS 1.1",
    "check:session_cookie_flags": "Add the missing cookie security flags",
}


def _action_name(key: tuple[str, str], members) -> str:
    titles = {f.title for f in members}
    if len(titles) == 1:
        return titles.pop()
    finding_type, detail = key
    if detail.startswith("header:"):
        return f"Add the {detail.split(':', 1)[1]} header"
    if detail.startswith("port:"):
        return f"Close or restrict port {detail.split(':', 1)[1]}"
    return GROUP_ACTIONS.get(detail, Finding.FindingType(finding_type).label)


def _projected_score(per_asset: dict, fixed: set, at_risk_count: int) -> float | None:
    """
    The organization's score if the `fixed` findings were gone. Averaged
    over the hosts at risk TODAY (a host that is fixed counts as 100), so
    fixing something can only ever raise the projection; then the same
    cap as the real grade: an open critical holds it at C, a high at B.
    """
    if not at_risk_count:
        return None
    total = 0
    severities = set()
    for findings in per_asset.values():
        remaining = [f for f in findings if f.id not in fixed]
        total += calculate_risk_score(remaining)
        severities.update(f.severity for f in remaining)
    score = total / at_risk_count
    if Finding.Severity.CRITICAL in severities:
        score = min(score, GRADE_CAPS[Finding.Severity.CRITICAL])
    elif Finding.Severity.HIGH in severities:
        score = min(score, GRADE_CAPS[Finding.Severity.HIGH])
    return round(score, 1)


def build_fix_plan(organization) -> dict:
    """
    Open issues (low and above) grouped into the actions that fix them
    ("enable HSTS on these 14 hosts"), most urgent first: worst severity, then whether a
    crown-jewel host is affected, then how many issues the action closes.
    Each step carries the grade the organization would have once it and
    every step before it is done.
    """
    findings = list(
        Finding.objects.counts_toward_risk()
        .filter(asset__organization=organization, asset__is_active=True)
        .select_related("asset")
    )
    sla = organization.sla_policy
    kev = kev_index()
    per_asset: dict = defaultdict(list)
    groups: dict = defaultdict(list)
    for finding in findings:
        per_asset[finding.asset_id].append(finding)
        # Info findings (a healthy certificate, a web port on a web
        # server) still count in the score but aren't work to do.
        if finding.severity != Finding.Severity.INFO:
            groups[_fix_key(finding)].append(finding)

    plan = []
    for key, members in groups.items():
        worst = max(members, key=lambda f: SEVERITY_RANK[f.severity])
        hosts = {f.asset_id: f.asset for f in members}
        members.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.asset.value))
        plan.append({
            "action": _action_name(key, members),
            "finding_type": key[0],
            "severity": worst.severity,
            "remediation": guidance_for(worst)["remediation"],
            "issues": len(members),
            "hosts": len(hosts),
            "crown_jewels": sum(1 for a in hosts.values() if a.criticality == Asset.Criticality.CROWN_JEWEL),
            "overdue": sum(1 for f in members if is_overdue(f, sla=sla)),
            # Attackers are known to exploit at least one of these CVEs.
            "known_exploited": sum(1 for f in members if any(cve in kev for cve in f.cves)),
            "items": [
                {
                    "finding": f.id, "asset": f.asset_id, "asset_value": f.asset.value,
                    "title": f.title, "severity": f.severity,
                }
                for f in members[:FIX_PLAN_ITEMS]
            ],
            "_ids": {f.id for f in members},
        })

    # Known-exploited first (CISA KEV), then worst severity, then crown jewels, then the widest fix.
    plan.sort(key=lambda step: (
        -min(step["known_exploited"], 1), -SEVERITY_RANK[step["severity"]], -min(step["crown_jewels"], 1),
        -step["issues"], step["action"],
    ))

    at_risk = len(per_asset)
    current = _projected_score(per_asset, set(), at_risk)
    fixed: set = set()
    for step in plan:
        fixed |= step.pop("_ids")
        step["score_after"] = _projected_score(per_asset, fixed, at_risk)
        step["grade_after"] = grade_for_score(round(step["score_after"])) if step["score_after"] is not None else None

    return {
        "current_score": current,
        "current_grade": grade_for_score(round(current)) if current is not None else None,
        "open_issues": len(findings),
        "steps": plan,
    }


def build_technologies(organization) -> list[dict]:
    """Every piece of software seen, with the hosts it runs on."""
    rows: dict = {}
    technologies = (
        Technology.objects.filter(asset__organization=organization, asset__is_active=True)
        .select_related("asset")
        .order_by("name", "version", "asset__value")
    )
    for tech in technologies:
        row = rows.setdefault((tech.name, tech.version), {
            "name": tech.name, "version": tech.version, "category": tech.category, "hosts": [],
        })
        row["hosts"].append({"id": tech.asset_id, "value": tech.asset.value})
    result = list(rows.values())
    for row in result:
        row["host_count"] = len(row["hosts"])
    result.sort(key=lambda r: (-r["host_count"], r["name"].lower(), r["version"]))
    return result


def build_services(organization) -> list[dict]:
    """Every open port seen, with the hosts it is open on, riskiest first."""
    rows: dict = {}
    ports = (
        Finding.objects.filter(
            asset__organization=organization, asset__is_active=True,
            is_active=True, finding_type=Finding.FindingType.OPEN_PORT,
        )
        .select_related("asset")
        .order_by("asset__value")
    )
    for finding in ports:
        raw = finding.raw_data or {}
        key = (str(raw.get("port", "")), raw.get("protocol", "tcp"))
        row = rows.setdefault(key, {
            "port": raw.get("port"), "protocol": key[1], "service": raw.get("service") or "unknown",
            "severity": finding.severity, "hosts": [],
        })
        if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[row["severity"]]:
            row["severity"] = finding.severity
        row["hosts"].append({
            "id": finding.asset_id, "value": finding.asset.value,
            "product": raw.get("product", ""), "finding": finding.id, "status": finding.status,
        })
    result = list(rows.values())
    for row in result:
        row["host_count"] = len(row["hosts"])
    result.sort(key=lambda r: (-SEVERITY_RANK[r["severity"]], -r["host_count"], str(r["port"])))
    return result


def build_certificates(organization) -> list[dict]:
    """Every TLS certificate seen, soonest to expire first."""
    now = timezone.now()
    result = []
    certificates = Finding.objects.filter(
        asset__organization=organization, asset__is_active=True,
        is_active=True, finding_type=Finding.FindingType.EXPIRED_SSL,
    ).select_related("asset")
    for finding in certificates:
        not_after = (finding.raw_data or {}).get("not_after")
        try:
            expires = datetime.fromisoformat(not_after)
        except (TypeError, ValueError):
            continue
        result.append({
            "asset": finding.asset_id,
            "asset_value": finding.asset.value,
            "finding": finding.id,
            "not_after": expires.isoformat(),
            # Counted now, not when the scan ran; whole days either way
            # ("expired 12 days ago", not 13 because of the hours).
            "days_remaining": (expires - now).days if expires >= now else -(now - expires).days,
            "severity": finding.severity,
        })
    result.sort(key=lambda r: r["not_after"])
    return result


def build_heatmap(organization) -> dict:
    """
    Open issues (low and above) counted by kind and severity: one row
    per kind of issue, heaviest first, so the darkest cells show where
    the trouble is concentrated.
    """
    from django.db.models import Count

    counts = (
        Finding.objects.counts_toward_risk()
        .filter(asset__organization=organization, asset__is_active=True)
        .exclude(severity=Finding.Severity.INFO)
        .values_list("finding_type", "severity")
        .annotate(count=Count("id"))
    )
    severities = [s for s in reversed(Finding.Severity.values) if s != Finding.Severity.INFO]
    rows: dict = {}
    for finding_type, severity, count in counts:
        row = rows.setdefault(finding_type, {
            "finding_type": finding_type,
            "label": Finding.FindingType(finding_type).label,
            "counts": {s: 0 for s in severities},
            "total": 0,
        })
        row["counts"][severity] = count
        row["total"] += count
    weight = {s: 10 ** (len(severities) - i) for i, s in enumerate(severities)}
    ordered = sorted(
        rows.values(), key=lambda r: (-sum(weight[s] * n for s, n in r["counts"].items()), r["label"])
    )
    return {"severities": severities, "rows": ordered}
