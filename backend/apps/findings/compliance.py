"""
Which well-known security frameworks each kind of finding relates to.

This is an indicative mapping to help people see why an issue matters
and to prioritise -- "this is an OWASP Top 10 item", "this is the CIS
safeguard about DMARC". It is not a compliance assessment: passing
every check here does not make anyone compliant with anything.

MITRE ATT&CK is listed alongside the compliance frameworks but answers
a different question: not "which rule does this break" but "which
attacker technique does this open the door to".
"""

from django.db.models import Count

from .models import Finding

FRAMEWORKS = {
    "owasp": "OWASP Top 10 (2021)",
    "cis": "CIS Critical Security Controls v8",
    "iso27001": "ISO/IEC 27001:2022 Annex A",
    "pci": "PCI DSS v4.0",
    "attack": "MITRE ATT&CK (Enterprise)",
}

CONTROLS = {
    "owasp:A01": "Broken Access Control",
    "owasp:A02": "Cryptographic Failures",
    "owasp:A05": "Security Misconfiguration",
    "owasp:A06": "Vulnerable and Outdated Components",
    "owasp:A07": "Identification and Authentication Failures",
    "cis:1.1": "Establish and maintain a detailed enterprise asset inventory",
    "cis:2.2": "Ensure authorized software is currently supported",
    "cis:3.3": "Configure data access control lists",
    "cis:3.10": "Encrypt sensitive data in transit",
    "cis:4.1": "Establish and maintain a secure configuration process",
    "cis:4.4": "Implement and manage a firewall on servers",
    "cis:7": "Continuous vulnerability management",
    "cis:9.5": "Implement DMARC",
    "cis:12": "Network infrastructure management",
    "iso27001:A.5.7": "Threat intelligence",
    "iso27001:A.5.9": "Inventory of information and other associated assets",
    "iso27001:A.5.14": "Information transfer",
    "iso27001:A.8.3": "Information access restriction",
    "iso27001:A.8.4": "Access to source code",
    "iso27001:A.8.8": "Management of technical vulnerabilities",
    "iso27001:A.8.9": "Configuration management",
    "iso27001:A.8.20": "Networks security",
    "iso27001:A.8.24": "Use of cryptography",
    "iso27001:A.8.26": "Application security requirements",
    "pci:1.3": "Network access to and from the cardholder data environment is restricted",
    "pci:2.2": "System components are configured and managed securely",
    "pci:3.6": "Cryptographic keys used to protect stored account data are secured",
    "pci:4.2": "Strong cryptography protects data during transmission",
    "pci:5.4": "Anti-phishing mechanisms protect users against phishing attacks",
    "pci:6.2": "Bespoke and custom software is developed securely",
    "pci:6.3": "Security vulnerabilities are identified and addressed",
    "pci:6.4": "Public-facing web applications are protected against attacks",
    "pci:7.2": "Access to system components and data is appropriately defined and assigned",
    "pci:11.3": "External and internal vulnerabilities are regularly identified and addressed",
    "pci:12.5": "An inventory of in-scope system components is maintained",
    "attack:T1190": "Exploit Public-Facing Application",
    "attack:T1133": "External Remote Services",
    "attack:T1078": "Valid Accounts",
    "attack:T1557": "Adversary-in-the-Middle",
    "attack:T1539": "Steal Web Session Cookie",
    "attack:T1552.001": "Unsecured Credentials: Credentials In Files",
    "attack:T1566": "Phishing",
    "attack:T1583.001": "Acquire Infrastructure: Domains",
    "attack:T1584.001": "Compromise Infrastructure: Domains",
    "attack:T1590.002": "Gather Victim Network Information: DNS",
    "attack:T1189": "Drive-by Compromise",
    "attack:T1588.004": "Obtain Capabilities: Digital Certificates",
    "attack:T1530": "Data from Cloud Storage",
}

T = Finding.FindingType
MAPPING: dict[str, list[str]] = {
    T.OPEN_PORT: ["owasp:A05", "cis:4.4", "iso27001:A.8.20", "pci:1.3", "attack:T1133", "attack:T1190"],
    T.EXPOSED_SERVICE: ["owasp:A05", "cis:4.4", "iso27001:A.8.20", "pci:1.3", "attack:T1133", "attack:T1078"],
    T.MISSING_HEADER: ["owasp:A05", "cis:4.1", "iso27001:A.8.9", "pci:6.4", "attack:T1189", "attack:T1557"],
    T.EXPIRED_SSL: ["owasp:A02", "cis:3.10", "iso27001:A.8.24", "pci:4.2", "attack:T1557"],
    T.WEAK_TLS: ["owasp:A02", "cis:3.10", "iso27001:A.8.24", "pci:4.2", "attack:T1557"],
    T.NO_HTTPS: ["owasp:A02", "cis:3.10", "iso27001:A.8.24", "pci:4.2", "attack:T1557"],
    T.INSECURE_COOKIE: ["owasp:A07", "iso27001:A.8.26", "pci:6.2", "attack:T1539"],
    T.CORS: ["owasp:A01", "iso27001:A.8.26", "pci:6.2", "attack:T1539"],
    T.NUCLEI_MATCH: ["owasp:A06", "cis:7", "iso27001:A.8.8", "pci:6.3", "pci:11.3", "attack:T1190"],
    T.OUTDATED_SOFTWARE: ["owasp:A06", "cis:2.2", "cis:7", "iso27001:A.8.8", "pci:6.3", "attack:T1190"],
    T.EXPOSED_FILE: ["owasp:A05", "cis:4.1", "iso27001:A.8.9", "pci:2.2", "attack:T1552.001"],
    T.SUBDOMAIN_TAKEOVER: ["owasp:A05", "cis:1.1", "iso27001:A.5.9", "attack:T1584.001"],
    T.ZONE_TRANSFER: ["owasp:A05", "cis:12", "iso27001:A.8.20", "pci:2.2", "attack:T1590.002"],
    T.EMAIL_SECURITY: ["cis:9.5", "iso27001:A.5.14", "pci:5.4", "attack:T1566"],
    T.SECURITY_TXT: ["cis:7", "iso27001:A.8.8"],
    T.LOOKALIKE_DOMAIN: ["iso27001:A.5.7", "pci:5.4", "attack:T1583.001", "attack:T1566"],
    T.EXPOSED_PANEL: ["owasp:A05", "owasp:A07", "cis:4.4", "iso27001:A.8.20", "pci:1.3", "attack:T1133", "attack:T1190"],
    T.API_EXPOSURE: ["owasp:A01", "owasp:A05", "iso27001:A.8.26", "pci:6.4", "attack:T1190"],
    T.DNS_HYGIENE: ["owasp:A05", "cis:4.1", "iso27001:A.8.9", "attack:T1557"],
    T.EXPOSED_SECRET: ["owasp:A02", "owasp:A05", "cis:3.3", "iso27001:A.8.4", "pci:3.6", "attack:T1552.001"],
    T.PUBLIC_BUCKET: ["owasp:A01", "owasp:A05", "cis:3.3", "iso27001:A.8.3", "pci:7.2", "attack:T1530"],
    T.POLICY_VIOLATION: ["iso27001:A.8.9", "cis:4.1"],
    T.DOMAIN_REGISTRATION: ["cis:1.1", "iso27001:A.5.9", "attack:T1584.001"],
    T.UNUSUAL_CERT: ["owasp:A02", "iso27001:A.5.7", "attack:T1588.004", "attack:T1557"],
    # Inventory: evidence that the asset inventory is kept, not issues.
    T.SUBDOMAIN_DISCOVERED: ["cis:1.1", "iso27001:A.5.9", "pci:12.5"],
    T.DNS_CHANGE: ["cis:1.1", "iso27001:A.5.9"],
    T.CERT_ISSUED: ["cis:1.1", "iso27001:A.5.9"],
}

DISCLAIMER = (
    "An indicative mapping to help prioritise, not a compliance assessment. "
    "Passing these checks does not on its own make an organization compliant."
)


def controls_for(finding_type: str) -> list[dict]:
    return [
        {"id": control, "framework": control.split(":")[0], "code": control.split(":")[1], "name": CONTROLS[control]}
        for control in MAPPING.get(finding_type, [])
    ]


def finding_types_for(control: str) -> list[str]:
    return [finding_type for finding_type, controls in MAPPING.items() if control in controls]


def build_compliance(organization) -> dict:
    """Every mapped control, with how many open issues bear on it."""
    # Info findings (a valid certificate, a web server on port 443) are
    # records, not problems: they don't count against a control.
    open_by_type = dict(
        Finding.objects.counts_toward_risk()
        .filter(asset__organization=organization, asset__is_active=True)
        .exclude(severity=Finding.Severity.INFO)
        .values_list("finding_type")
        .annotate(count=Count("id"))
    )
    monitored_types = set(MAPPING)

    frameworks = []
    for key, name in FRAMEWORKS.items():
        controls = []
        for control, control_name in CONTROLS.items():
            if not control.startswith(f"{key}:"):
                continue
            types = finding_types_for(control)
            issue_types = [t for t in types if t not in Finding.INVENTORY_TYPES]
            open_issues = sum(open_by_type.get(t, 0) for t in issue_types)
            controls.append({
                "id": control,
                "code": control.split(":")[1],
                "name": control_name,
                "open_issues": open_issues,
                "checks": len([t for t in types if t in monitored_types]),
                # Controls only covered by inventory have no issues to show.
                "inventory_only": not issue_types,
            })
        frameworks.append({
            "id": key,
            "name": name,
            "controls": controls,
            "controls_with_issues": sum(1 for c in controls if c["open_issues"]),
        })
    return {"frameworks": frameworks, "disclaimer": DISCLAIMER}
