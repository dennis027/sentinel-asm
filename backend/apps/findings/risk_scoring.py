"""
Risk scoring: turns an asset's active findings into a 0-100 score and
a letter grade (A+ through F), matching the original product brief.

Deliberately a simple, fully transparent weighted-deduction formula
rather than anything more elaborate -- an explainable score a security
analyst can immediately understand and defend ("why is this a C?")
beats a marginally more accurate black-box one. This is a pure-function
module with zero DB access, so it's trivially unit-testable and easy
to tune later without touching the model/API layer that calls it.
"""

from apps.findings.models import Finding

# Points deducted per active finding, by severity. Only ACTIVE, OPEN
# findings count -- a resolved finding (is_active=False) or one an
# analyst has accepted / marked false-positive no longer affects the
# score, which is exactly the point of tracking resolution and triage
# instead of deleting rows.
SEVERITY_DEDUCTIONS = {
    Finding.Severity.CRITICAL: 25,
    Finding.Severity.HIGH: 15,
    Finding.Severity.MEDIUM: 8,
    Finding.Severity.LOW: 3,
    Finding.Severity.INFO: 1,
}

STARTING_SCORE = 100
MINIMUM_SCORE = 0

# (minimum score to earn this grade, grade label) -- checked in order,
# first match wins. Deliberately generous at the top (A+ allows a
# couple of low-severity findings, not just a spotless asset) and
# steep at the bottom (any critical finding alone knocks a perfect
# asset down to a C, not just a B).
GRADE_THRESHOLDS = [
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (50, "C"),
    (30, "D"),
    (0, "F"),
]


# Highest score allowed while an issue of this severity is open: just
# below the next grade up (C tops out at 69, B at 84). An average or a
# sum of small deductions must never let one serious exposure look fine.
GRADE_CAPS = {Finding.Severity.CRITICAL: 69, Finding.Severity.HIGH: 84}


def apply_grade_cap(score: float, has_critical: bool, has_high: bool) -> float:
    if has_critical:
        return min(score, GRADE_CAPS[Finding.Severity.CRITICAL])
    if has_high:
        return min(score, GRADE_CAPS[Finding.Severity.HIGH])
    return score


def calculate_risk_score(active_findings) -> int:
    """
    active_findings: an iterable of Finding objects (or anything with a
    .severity attribute) -- caller is responsible for filtering to
    active, open findings first (see Asset.risk_score), this function
    doesn't do that filtering itself so it stays a pure, easily-tested
    function rather than one that assumes a specific queryset shape.
    """
    score = STARTING_SCORE
    severities = set()
    for finding in active_findings:
        score -= SEVERITY_DEDUCTIONS.get(finding.severity, 0)
        severities.add(finding.severity)
    score = max(MINIMUM_SCORE, score)
    return int(apply_grade_cap(
        score, Finding.Severity.CRITICAL in severities, Finding.Severity.HIGH in severities
    ))


def grade_for_score(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"  # unreachable given threshold 0 exists, but explicit fallback