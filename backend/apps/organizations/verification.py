"""
Domain-ownership check: looks for the organization's verification TXT
record in public DNS. Kept as a plain function (no model/HTTP concerns)
so the view can call it and tests can patch it.
"""

import dns.exception
import dns.resolver

LOOKUP_TIMEOUT_SECONDS = 5


def has_verification_record(organization) -> bool:
    resolver = dns.resolver.Resolver()
    resolver.timeout = LOOKUP_TIMEOUT_SECONDS
    resolver.lifetime = LOOKUP_TIMEOUT_SECONDS

    try:
        answers = resolver.resolve(organization.verification_record_name, "TXT")
    except dns.exception.DNSException:
        return False

    expected = organization.verification_record_value
    for answer in answers:
        # A TXT record can be split into several strings on the wire --
        # join them before comparing.
        value = b"".join(answer.strings).decode("utf-8", "ignore").strip()
        if value == expected:
            return True
    return False
