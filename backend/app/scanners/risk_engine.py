from collections import Counter

from app.models.result import Finding


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def calculate_risk(findings: list[Finding]) -> dict:
    counts = Counter(
        finding.severity.upper()
        for finding in findings
    )

    for severity in SEVERITY_ORDER:
        counts.setdefault(severity, 0)

    if not findings:
        overall_severity = "INFO"
    else:
        overall_severity = max(
            (
                finding.severity.upper()
                for finding in findings
            ),
            key=lambda severity: SEVERITY_ORDER.get(severity, 0),
        )

    return {
        "severity": overall_severity,
        "counts": {
            "CRITICAL": counts["CRITICAL"],
            "HIGH": counts["HIGH"],
            "MEDIUM": counts["MEDIUM"],
            "LOW": counts["LOW"],
            "INFO": counts["INFO"],
        },
    }