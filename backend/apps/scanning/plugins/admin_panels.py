"""
Is a management interface open to the whole internet?

Database admin tools, CI servers, dashboards and server control panels
are meant for a handful of staff. Reachable from anywhere, they are the
first thing attackers try passwords and known exploits against -- and
several of them (phpMyAdmin, Jenkins, Tomcat manager) have a long
history of both.

Like the exposed-files check, a panel only counts when the page itself
says what it is: plenty of sites answer every path with their home page.
"""

import re
from dataclasses import dataclass

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .http_util import fetch
from .registry import register_scanner

S = Finding.Severity


@dataclass
class Panel:
    check: str
    name: str
    paths: tuple[str, ...]
    # Text that appears on the real thing (case-insensitive regex).
    signature: str
    severity: str
    what: str


PANELS = [
    Panel("phpmyadmin", "phpMyAdmin", ("/phpmyadmin/", "/phpMyAdmin/", "/pma/"), r"phpmyadmin", S.HIGH,
          "a database administration tool"),
    Panel("adminer", "Adminer", ("/adminer.php", "/adminer/"), r"<title>[^<]*adminer|adminer\.org", S.HIGH,
          "a database administration tool"),
    Panel("pgadmin", "pgAdmin", ("/pgadmin4/", "/pgadmin/"), r"pgadmin", S.HIGH, "a PostgreSQL administration tool"),
    Panel("jenkins", "Jenkins", ("/jenkins/", "/login?from=%2F", "/"), r"x-jenkins|<title>[^<]*jenkins|jenkins-head",
          S.HIGH, "the build server that holds deployment credentials"),
    Panel("tomcat_manager", "Tomcat Manager", ("/manager/html",), r"tomcat web application manager|tomcat manager",
          S.HIGH, "the Apache Tomcat application manager"),
    Panel("webmin", "Webmin", (":10000/",), r"webmin", S.HIGH, "a server control panel"),
    Panel("cpanel", "cPanel", (":2083/", ":2087/"), r"cpanel", S.MEDIUM, "a hosting control panel"),
    Panel("grafana", "Grafana", ("/login", "/grafana/login"), r"grafana", S.MEDIUM, "a monitoring dashboard"),
    Panel("kibana", "Kibana", ("/app/kibana", "/login"), r"kibana|kbn-name", S.MEDIUM, "a log and data dashboard"),
    Panel("rabbitmq", "RabbitMQ management", (":15672/",), r"rabbitmq management", S.MEDIUM, "a message-queue console"),
    Panel("wordpress_admin", "WordPress sign-in", ("/wp-login.php",), r"wp-submit|wordpress", S.LOW,
          "the WordPress administrator sign-in page"),
]


def assess(host: str, panel: Panel, path: str, status: int, body: str, headers=None) -> RawFinding | None:
    if status not in (200, 401, 403):
        return None
    header_text = " ".join(f"{k}: {v}" for k, v in (headers.items() if headers else []))
    if not re.search(panel.signature, body + " " + header_text, re.IGNORECASE):
        return None
    blocked = status in (401, 403)
    return RawFinding(
        finding_type=Finding.FindingType.EXPOSED_PANEL,
        identifier=panel.check,
        # Answering with "forbidden" means it is there but someone limited it: lower.
        severity=S.LOW if blocked and panel.severity != S.LOW else panel.severity,
        title=f"{panel.name} is reachable from the internet",
        description=(
            f"https://{host}{path if not path.startswith(':') else path} serves {panel.what} ({panel.name})"
            + (", though it asked for authorisation first." if blocked else ".")
        ),
        raw_data={"check": "exposed_panel", "panel": panel.check, "path": path, "status": status},
    )


@register_scanner
class AdminPanelScanner(BaseScanner):
    name = "admin_panels"
    category = "web"
    label = "Exposed admin panels"
    description = (
        "Looks for management interfaces that should not face the internet: phpMyAdmin, Jenkins, Grafana, "
        "Tomcat manager, Webmin and similar."
    )
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.EXPOSED_PANEL]

    def run(self, target) -> list[RawFinding]:
        host = target.value
        findings = []
        for panel in PANELS:
            for path in panel.paths:
                if path.startswith(":"):
                    # A different port: the host part changes, the path is "/".
                    port, _, rest = path[1:].partition("/")
                    url_host, url_path = f"{host}:{port}", "/" + rest
                else:
                    url_host, url_path = host, path
                try:
                    page = fetch(url_host, url_path, timeout=6)
                except RuntimeError:
                    continue
                finding = assess(host, panel, path, page.status, page.body, page.headers)
                if finding:
                    findings.append(finding)
                    break
        return findings
