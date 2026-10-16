"""
Time-based one-time passwords (RFC 6238), the six-digit codes every
authenticator app produces. Small enough to implement here rather than
add a dependency: HMAC-SHA1 over a 30-second counter.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6
# Accept the code from one step either side, for phone clocks that drift.
WINDOW = 1


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**DIGITS).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((now if now is not None else time.time()) // STEP_SECONDS)


def matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    """The time-step `code` is valid for, or None if it isn't valid now."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != DIGITS:
        return None
    step = current_step(now)
    for candidate in range(step - WINDOW, step + WINDOW + 1):
        if hmac.compare_digest(code_at(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(secret: str, account: str, issuer: str = "Densight") -> str:
    """The otpauth:// link an authenticator app reads from the QR code."""
    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&digits={DIGITS}&period={STEP_SECONDS}"


def qr_svg(text: str) -> str:
    """The QR code for `text`, as an SVG document."""
    from reportlab.graphics import renderSVG
    from reportlab.graphics.barcode.qr import QrCodeWidget
    from reportlab.graphics.shapes import Drawing

    widget = QrCodeWidget(text, barLevel="M")
    x1, y1, x2, y2 = widget.getBounds()
    size = 200
    drawing = Drawing(size, size, transform=[size / (x2 - x1), 0, 0, size / (y2 - y1), 0, 0])
    drawing.add(widget)
    svg = renderSVG.drawToString(drawing)
    # Drop the XML prolog and doctype so it can be placed inline in a page.
    return svg[svg.index("<svg"):]
