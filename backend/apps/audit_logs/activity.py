from .models import ActivityEvent


def record(user, organization, verb: str, summary: str, finding=None) -> ActivityEvent:
    """Adds one line to the organization's activity log. `user` None means the system did it."""
    return ActivityEvent.objects.create(
        organization=organization,
        finding=finding,
        actor=user if getattr(user, "is_authenticated", False) else None,
        actor_name=getattr(user, "username", "") or "System",
        verb=verb,
        summary=summary[:500],
    )
