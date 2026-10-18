"""
Does the site publish a map of its own API?

Swagger/OpenAPI documentation and GraphQL introspection list every
endpoint, parameter and field. That is useful to developers and
equally useful to an attacker looking for the one endpoint that skips
an authorisation check. Public APIs may publish theirs on purpose
(mark the finding as accepted); internal ones usually shouldn't.

Introspection is checked with the standard read-only query for type
names; nothing is changed on the server.
"""

import json

from apps.findings.models import Finding

from .base import BaseScanner, RawFinding
from .http_util import fetch
from .registry import register_scanner

S = Finding.Severity

SPEC_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs", "/api-docs", "/api/swagger.json",
              "/api/openapi.json", "/api/schema/")
UI_PATHS = ("/swagger-ui/", "/swagger-ui.html", "/swagger/index.html", "/docs", "/api/docs/", "/redoc")
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")
INTROSPECTION = json.dumps({"query": "{ __schema { queryType { name } types { name } } }"}).encode()


def spec_endpoints(body: str) -> int | None:
    """Number of paths if this is an OpenAPI/Swagger document, else None."""
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc) or not isinstance(doc.get("paths"), dict):
        return None
    return len(doc["paths"])


def introspection_types(body: str) -> int | None:
    try:
        doc = json.loads(body)
        types = doc["data"]["__schema"]["types"]
    except (ValueError, KeyError, TypeError):
        return None
    return len(types) if isinstance(types, list) else None


@register_scanner
class ApiExposureScanner(BaseScanner):
    name = "api_exposure"
    category = "web"
    label = "API documentation & GraphQL"
    description = "Finds published OpenAPI/Swagger documentation and GraphQL APIs that answer introspection queries."
    applies_to = "asset"
    owned_finding_types = [Finding.FindingType.API_EXPOSURE]

    def run(self, target) -> list[RawFinding]:
        host = target.value
        findings = []

        for path in SPEC_PATHS:
            page = self._get(host, path)
            count = spec_endpoints(page.body) if page and page.status == 200 else None
            if count is not None:
                findings.append(RawFinding(
                    finding_type=Finding.FindingType.API_EXPOSURE, identifier="openapi_spec", severity=S.MEDIUM,
                    title="API specification is public",
                    description=f"https://{host}{path} publishes an OpenAPI/Swagger document describing {count} endpoint(s).",
                    raw_data={"check": "openapi_spec", "path": path, "endpoints": count},
                ))
                break

        if not findings:
            for path in UI_PATHS:
                page = self._get(host, path)
                if page and page.status == 200 and any(m in page.body.lower() for m in ("swagger-ui", "redoc", "swaggerui")):
                    findings.append(RawFinding(
                        finding_type=Finding.FindingType.API_EXPOSURE, identifier="api_docs_ui", severity=S.LOW,
                        title="Interactive API documentation is public",
                        description=f"https://{host}{path} serves interactive API documentation (Swagger UI or ReDoc).",
                        raw_data={"check": "api_docs_ui", "path": path},
                    ))
                    break

        for path in GRAPHQL_PATHS:
            try:
                page = fetch(host, path, timeout=8, method="POST", data=INTROSPECTION,
                             headers={"Content-Type": "application/json"})
            except RuntimeError:
                continue
            types = introspection_types(page.body) if page.status == 200 else None
            if types is not None:
                findings.append(RawFinding(
                    finding_type=Finding.FindingType.API_EXPOSURE, identifier="graphql_introspection",
                    severity=S.MEDIUM, title="GraphQL introspection is enabled",
                    description=f"https://{host}{path} answers introspection queries, revealing {types} types: "
                                "every query, mutation and field the API has.",
                    raw_data={"check": "graphql_introspection", "path": path, "types": types},
                ))
                break
        return findings

    @staticmethod
    def _get(host, path):
        try:
            return fetch(host, path, timeout=8)
        except RuntimeError:
            return None
