"""
/metrics, guarded. Prometheus output includes request counts per view
and scan/finding volumes -- not something to hand to the open internet.

- METRICS_TOKEN set: scrapers must send `Authorization: Bearer <token>`.
- METRICS_TOKEN unset: served only when DEBUG is on (local dev);
  otherwise 404, so a production deploy that forgot to configure a
  token fails closed.
"""

from django.conf import settings
from django.http import Http404, HttpResponse
from django.utils.crypto import constant_time_compare
from django_prometheus.exports import ExportToDjangoView


def metrics_view(request):
    token = settings.METRICS_TOKEN
    if token:
        supplied = request.headers.get("Authorization", "")
        if not constant_time_compare(supplied, f"Bearer {token}"):
            return HttpResponse(status=401, headers={"WWW-Authenticate": "Bearer"})
    elif not settings.DEBUG:
        raise Http404
    return ExportToDjangoView(request)
