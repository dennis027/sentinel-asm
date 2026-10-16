"""
Are the site's cookies protected?

A session cookie is what keeps a visitor logged in; whoever holds it
is that visitor. Three flags decide how easily it can be taken:

- Secure:   never sent over unencrypted HTTP
- HttpOnly: not readable by scripts on the page (so a script-injection
            flaw can't simply steal it)
- SameSite: not sent along with requests that other sites trigger

Reads the Set-Cookie headers of the home page. Cookies that are only
set after logging in are not seen.
"""

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .http_util import fetch
from .registry import register_scanner

# Cookie names that usually carry a login or session.
SESSION_HINTS = ("sess", "sid", "auth", "token", "jwt", "login", "remember")


def parse_cookie(header: str) -> tuple[str, set[str]]:
    """'sid=abc; Path=/; HttpOnly; SameSite=Lax' -> ('sid', {'path', 'httponly', 'samesite'})"""
    parts = [part.strip() for part in header.split(";")]
    name = parts[0].partition("=")[0].strip()
    attributes = {part.partition("=")[0].strip().lower() for part in parts[1:] if part}
    return name, attributes


def assess(host: str, set_cookie_headers: list[str]) -> list[RawFinding]:
    """Pure function: Set-Cookie header values -> findings (one per cookie)."""
    findings = []
    for header in set_cookie_headers:
        name, attributes = parse_cookie(header)
        if not name:
            continue
        missing = [flag for flag in ("Secure", "HttpOnly", "SameSite") if flag.lower() not in attributes]
        if not missing:
            continue

        is_session = any(hint in name.lower() for hint in SESSION_HINTS)
        serious = is_session and ("Secure" in missing or "HttpOnly" in missing)
        findings.append(RawFinding(
            finding_type=Finding.FindingType.INSECURE_COOKIE,
            identifier=name,
            severity=Finding.Severity.MEDIUM if serious else Finding.Severity.LOW,
            title=f"Cookie '{name}' is missing {', '.join(missing)}",
            description=(
                f"{host} sets the cookie '{name}' without the {', '.join(missing)} "
                f"flag{'s' if len(missing) > 1 else ''}."
                + (" Its name suggests it holds a session." if is_session else "")
            ),
            raw_data={
                "check": "session_cookie_flags" if serious else "cookie_flags",
                "cookie": name,
                "missing": missing,
            },
        ))
    return findings


@register_scanner
class CookieSecurityScanner(BaseScanner):
    name = "cookie_security"
    category = "web"
    label = "Cookie security"
    description = (
        "Checks that cookies, especially session cookies, are protected from theft and misuse."
    )
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.INSECURE_COOKIE]

    def run(self, target) -> list[RawFinding]:
        try:
            # HTTPS only: the Secure flag means nothing on a plain-HTTP site,
            # which the HTTPS enforcement scanner reports instead.
            page = fetch(target.value, schemes=("https",))
        except RuntimeError:
            return []
        return assess(target.value, page.headers.get_all("Set-Cookie") or [])
