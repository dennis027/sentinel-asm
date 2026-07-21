"""
Org-scoped access control. The core fix: every queryset that touches
tenant data must be filtered to organizations the requesting user is
actually a member of -- IsAuthenticated alone (the only check that
existed before this) proves WHO you are, not WHICH org's data you're
allowed to see.

Superusers bypass scoping entirely (see all orgs) -- standard
admin/support-access pattern, not a loophole specific to this app.
"""

from apps.organizations.models import Membership


def get_user_org_ids(user):
    """
    Returns None (sentinel meaning "don't filter, show everything") for
    superusers, otherwise a queryset of organization IDs the user has
    ANY membership role in.
    """
    if user.is_superuser:
        return None
    return Membership.objects.filter(user=user).values_list("organization_id", flat=True)


def user_can_access_org(user, organization) -> bool:
    if user.is_superuser:
        return True
    return Membership.objects.filter(user=user, organization=organization).exists()


class OrgScopedQuerysetMixin:
    """
    Mix into any viewset whose queryset needs org-scoping. Set
    `org_field` to the ORM path from the model to Organization:
      - "pk" if the model IS Organization itself
      - "organization" if it has a direct FK (Asset, ScanJob, NotificationRule)
      - "asset__organization" if it's one hop further (Finding)

    Detail views (retrieve/update/delete) on an out-of-scope object
    correctly 404 rather than 403 -- get_object() runs against the
    already-filtered queryset, so an object outside the user's orgs
    simply isn't there, which avoids confirming to an unauthorized
    caller that a given ID even exists.
    """

    org_field: str = "organization"

    def get_queryset(self):
        qs = super().get_queryset()
        org_ids = get_user_org_ids(self.request.user)
        if org_ids is None:
            return qs
        return qs.filter(**{f"{self.org_field}__in": org_ids})