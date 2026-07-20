def get_client_ip(request) -> str | None:
    """
    Prefers X-Forwarded-For (set by a reverse proxy like nginx in front
    of the API) over REMOTE_ADDR, which would otherwise just be the
    proxy's own address. Takes the first IP in the chain -- the
    original client, per the standard convention.
    """
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def get_user_agent(request) -> str:
    return request.META.get("HTTP_USER_AGENT", "")[:512]