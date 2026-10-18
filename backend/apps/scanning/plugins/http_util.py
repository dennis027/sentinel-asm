"""
One small HTTP request (GET, or POST for the GraphQL check) shared by the scanners that read a page or its
headers (takeover, outdated software, security.txt). Not a scanner
itself -- it registers nothing.

Deliberately forgiving about certificates (a host with a broken
certificate still has headers worth reading; the TLS scanners report
the certificate) and deliberately strict about redirects: it only
follows one to the same site, so a target can't bounce the scanner to
some other host, least of all an internal one.
"""

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

USER_AGENT = "densight/1.0"
MAX_BODY_BYTES = 64 * 1024


@dataclass
class Page:
    status: int
    headers: object  # http.client.HTTPMessage -- .get() is case-insensitive
    body: str
    url: str


def _same_site(first: str, second: str) -> bool:
    first, second = first.lower(), second.lower()
    return first == second or first == f"www.{second}" or second == f"www.{first}"


class _SameSiteRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _same_site(urlsplit(req.full_url).hostname or "", urlsplit(newurl).hostname or ""):
            return super().redirect_request(req, fp, code, msg, headers, newurl)
        return None  # surfaces as the 3xx response itself


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(
    host: str,
    path: str = "/",
    timeout: float = 10,
    headers: dict[str, str] | None = None,
    schemes: tuple[str, ...] = ("https", "http"),
    follow_redirects: bool = True,
    method: str = "GET",
    data: bytes | None = None,
    max_bytes: int = MAX_BODY_BYTES,
) -> Page:
    """
    GETs host/path over the first of `schemes` that answers (https,
    then http, by default). Any HTTP response -- including 403, 404
    and 5xx -- is returned: the server answered, and what it said is
    the data. With follow_redirects=False a redirect is returned as
    the 3xx response it is. Raises RuntimeError only when the host
    can't be reached at all.
    """
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
        _SameSiteRedirects if follow_redirects else _NoRedirects,
    )
    last_error: Exception | None = None
    for scheme in schemes:
        request = urllib.request.Request(
            f"{scheme}://{host}{path}", headers={"User-Agent": USER_AGENT, **(headers or {})},
            method=method, data=data,
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                return _page(response, max_bytes)
        except urllib.error.HTTPError as response:
            return _page(response, max_bytes)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            last_error = exc
    raise RuntimeError(f"Could not reach {host}: {last_error}")


def _page(response, max_bytes: int = MAX_BODY_BYTES) -> Page:
    try:
        body = response.read(max_bytes).decode("utf-8", "replace")
    except OSError:
        body = ""
    return Page(status=response.getcode() or 0, headers=response.headers, body=body, url=response.geturl())
