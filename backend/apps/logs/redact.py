"""
Masking secrets out of logs before they are stored.

Applications log more than they should: a request body with a password
in it, a URL with an API key, an "Authorization: Bearer ..." header.
Kept in a log store, those become a second copy of the secret that more
people can read. Everything is masked here, before it is saved, and the
kinds found are recorded so the "secrets in logs" detection can tell
the team to fix the code that wrote them.
"""

import re

# (kind, pattern, replacement). Groups named "keep" survive the masking.
PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
     "[REDACTED:private_key]"),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_key]"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "[REDACTED:github_token]"),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED:slack_token]"),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"), "[REDACTED:stripe_key]"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED:jwt]"),
    ("bearer_token", re.compile(r"(?P<keep>\bBearer\s+)[A-Za-z0-9._~+/=-]{12,}", re.I), r"\g<keep>[REDACTED:token]"),
    ("secret", re.compile(
        r"(?P<keep>\b(?:password|passwd|pwd|pass|secret|client_secret|api[_-]?key|apikey|access[_-]?token|"
        r"refresh[_-]?token|auth[_-]?token|token)\b[\"']?\s*[=:]\s*[\"']?)(?!\[REDACTED)[^\s\"'&,;}]{3,}",
        re.I,
    ), r"\g<keep>[REDACTED:secret]"),
]
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SENSITIVE_KEYS = re.compile(
    r"^(?:password|passwd|pwd|secret|client_secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|"
    r"authorization|cookie|set-cookie|token|private[_-]?key|card[_-]?number|cvv)$",
    re.I,
)


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        number = int(char)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def redact_text(text: str, found: set[str]) -> str:
    if not text or not isinstance(text, str):
        return text
    for kind, pattern, replacement in PATTERNS:
        text, count = pattern.subn(replacement, text)
        if count:
            found.add(kind)

    def card(match):
        digits = re.sub(r"\D", "", match.group(0))
        # Not a run of one repeated digit, which passes Luhn by accident.
        if 13 <= len(digits) <= 19 and _luhn(digits) and len(set(digits)) > 1:
            found.add("card_number")
            return "[REDACTED:card_number]"
        return match.group(0)

    return CARD.sub(card, text)


def redact_value(value, found: set[str], depth: int = 0):
    """Masks secrets anywhere in a decoded JSON value: by key name, and by pattern in strings."""
    if depth > 6:
        return value
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if SENSITIVE_KEYS.match(str(key)) and item not in (None, "", [], {}):
                found.add("password" if "pass" in str(key).lower() else "secret")
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = redact_value(item, found, depth + 1)
        return cleaned
    if isinstance(value, list):
        return [redact_value(item, found, depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value, found)
    return value
