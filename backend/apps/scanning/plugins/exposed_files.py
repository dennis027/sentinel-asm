"""
Looks for a short list of files that should never be downloadable from
a web server but very often are: a .git directory, a .env file, a
database dump, a backup of a config file.

Each of these hands an outsider source code, passwords or customer
data in one request, which is why they are the first thing automated
attackers try on every site they find.

A file only counts if its CONTENT looks like the real thing. Plenty of
sites answer every URL with a 200 and their home page; matching on the
status code alone would bury the real findings in false ones.

Nothing found here is stored: the finding records the path and what
kind of file it is, never its contents.
"""

import re
from dataclasses import dataclass
from typing import Callable

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .http_util import fetch
from .registry import register_scanner

_ENV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_GIT_HEAD = re.compile(r"^(ref: refs/\S+|[0-9a-f]{40})\s*$")


def _looks_like_env(body: str) -> bool:
    if "<html" in body.lower():
        return False
    lines = [line for line in body.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    return len(lines) >= 2 and all(_ENV_LINE.match(line.strip()) for line in lines[:5])


def _looks_like_sql(body: str) -> bool:
    upper = body.upper()
    return "<HTML" not in upper and any(mark in upper for mark in ("INSERT INTO", "CREATE TABLE", "-- MYSQL DUMP", "PGDUMP"))


@dataclass
class SensitiveFile:
    path: str
    check: str
    severity: str
    what: str
    is_real: Callable[[str], bool]


FILES = [
    SensitiveFile("/.git/HEAD", "git_exposed", Finding.Severity.CRITICAL, "Git repository",
                  lambda body: bool(_GIT_HEAD.match(body.strip()))),
    SensitiveFile("/.env", "env_exposed", Finding.Severity.CRITICAL, "Environment file (.env)", _looks_like_env),
    SensitiveFile("/wp-config.php.bak", "config_backup_exposed", Finding.Severity.CRITICAL,
                  "WordPress configuration backup", lambda body: "DB_PASSWORD" in body),
    SensitiveFile("/backup.sql", "database_dump_exposed", Finding.Severity.CRITICAL, "Database dump", _looks_like_sql),
    SensitiveFile("/dump.sql", "database_dump_exposed", Finding.Severity.CRITICAL, "Database dump", _looks_like_sql),
    SensitiveFile("/database.sql", "database_dump_exposed", Finding.Severity.CRITICAL, "Database dump", _looks_like_sql),
    SensitiveFile("/phpinfo.php", "phpinfo_exposed", Finding.Severity.MEDIUM, "PHP configuration page (phpinfo)",
                  lambda body: "phpinfo()" in body and "PHP Version" in body),
    SensitiveFile("/server-status", "server_status_exposed", Finding.Severity.MEDIUM, "Apache server-status page",
                  lambda body: "Apache Server Status" in body),
]


def assess(host: str, file: SensitiveFile, status: int, body: str) -> RawFinding | None:
    """Pure function: one probed path and its response -> a finding, or None."""
    if status != 200 or not file.is_real(body):
        return None
    return RawFinding(
        finding_type=Finding.FindingType.EXPOSED_FILE,
        identifier=file.path,
        severity=file.severity,
        title=f"{file.what} is publicly downloadable",
        description=f"https://{host}{file.path} returns a real {file.what.lower()} to anyone who asks for it.",
        raw_data={"check": file.check, "path": file.path},
    )


@register_scanner
class ExposedFilesScanner(BaseScanner):
    name = "exposed_files"
    category = "web"
    label = "Exposed sensitive files"
    description = (
        "Checks whether source code, password files or database dumps have been left downloadable."
    )
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.EXPOSED_FILE]

    def run(self, target) -> list[RawFinding]:
        host = target.value
        findings = []
        for index, file in enumerate(FILES):
            try:
                page = fetch(host, file.path)
            except RuntimeError:
                if index == 0:
                    return []  # no web server here: nothing to look for
                continue
            if finding := assess(host, file, page.status, page.body):
                findings.append(finding)
        return findings
