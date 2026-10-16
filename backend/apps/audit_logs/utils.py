from django.conf import settings


def get_client_ip(request) -> str | None:
    """
    X-Forwarded-For is only believed when settings.NUM_PROXIES says
    there are trusted reverse proxies in front of the API -- otherwise
    it's a client-supplied header and anyone could log whatever IP they
    like. With N trusted proxies, the client is the Nth address from
    the right (each proxy appends the address it saw), same rule DRF's
    throttles use for the same setting.
    """
    num_proxies = settings.NUM_PROXIES
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if num_proxies and forwarded_for:
        addresses = [a.strip() for a in forwarded_for.split(",") if a.strip()]
        if addresses:
            return addresses[-min(num_proxies, len(addresses))]
    return request.META.get("REMOTE_ADDR")


def get_user_agent(request) -> str:
    return request.META.get("HTTP_USER_AGENT", "")[:512]
