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

# Points deducted per active finding, by severity. Only ACTIVE findings
# count -- a resolved finding (is_active=False) no longer affects the
# score, which is exactly the point of tracking resolution instead of
# deleting rows.
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


def calculate_risk_score(active_findings) -> int:
    """
    active_findings: an iterable of Finding objects (or anything with a
    .severity attribute) -- caller is responsible for filtering to
    is_active=True first (see Asset.risk_score below), this function
    doesn't do that filtering itself so it stays a pure, easily-tested
    function rather than one that assumes a specific queryset shape.
    """
    score = STARTING_SCORE
    for finding in active_findings:
        score -= SEVERITY_DEDUCTIONS.get(finding.severity, 0)
    return max(MINIMUM_SCORE, score)


def grade_for_score(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"  # unreachable given threshold 0 exists, but explicit fallback