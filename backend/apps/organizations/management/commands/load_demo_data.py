"""
Loads a realistic, entirely fictional organization for demonstrations:

    python manage.py load_demo_data --owner <your username>

"Acme Retail" on acme-retail.example -- a reserved domain that does not
exist on the internet, so nothing here can ever point a scan at a real
system. It comes with three months of history: a risk trend that
improves over time, issues found and fixed, work assigned to people,
some of it overdue, scan runs, screenshots and an activity log. That
gives every screen something true-to-life to show.

Don't press "Run scan" on this organization: the domain doesn't
resolve, so real scans of it will simply fail. Use a domain you own
for a live scan.

Run it again with --reset to start the demo from a clean slate.
"""

import random
import shutil
import uuid
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.assets.models import Asset, Technology
from apps.audit_logs.models import ActivityEvent
from apps.findings.models import Finding, FindingComment, RiskSnapshot
from apps.findings.summary import build_risk_summary, record_snapshot
from apps.notifications.models import NotificationRule
from apps.organizations.deletion import delete_organization
from apps.organizations.models import Membership, Organization
from apps.scanning.models import ScanJob
from apps.scanning.plugins.registry import get_scanner, list_scanners

DOMAIN = "acme-retail.example"
NAME = "Acme Retail"
DEMO_ASSETS = Path(__file__).resolve().parents[2] / "demo_assets"

# host -> (technologies, screenshot image or None)
HOSTS = {
    "": ([("nginx", "1.24.0", "web-server")], "www"),
    "www": ([("nginx", "1.24.0", "web-server"), ("Next.js", "", "framework")], "www"),
    "shop": ([("Apache", "2.2.15", "web-server"), ("PHP", "7.4.33", "framework")], "shop"),
    "checkout": ([("nginx", "1.24.0", "web-server")], None),
    "api": ([("nginx", "1.24.0", "web-server"), ("Express", "", "framework")], None),
    "api-v1": ([("Microsoft-IIS", "8.5", "web-server"), ("ASP.NET", "4.0.30319", "framework")], None),
    "sso": ([("nginx", "1.24.0", "web-server")], "sso"),
    "mail": ([], None),
    "vpn": ([], None),
    "staging": ([("Jenkins", "2.346", "ci")], "staging"),
    "dev": ([("nginx", "1.14.0", "web-server")], None),
    "legacy": ([("Apache", "2.2.15", "web-server")], None),
    "grafana": ([("Grafana", "9.1.0", "monitoring")], "grafana"),
    "status": ([("Statuspage", "", "saas")], "status"),
    "blog": ([("cloudflare", "", "cdn"), ("WordPress", "6.4", "cms")], None),
    "docs": ([("Vercel", "", "hosting")], None),
    "cdn": ([("cloudflare", "", "cdn")], None),
    "careers": ([("Workable", "", "saas")], None),
    "promo2023": ([], None),
    "uploads": ([("nginx", "1.24.0", "web-server")], None),
    "db-backup": ([], None),
    "metrics": ([], None),
    "intranet": ([("Microsoft-IIS", "10.0", "web-server")], None),
    "support": ([("Zendesk", "", "saas")], None),
    "pay": ([("nginx", "1.24.0", "web-server")], None),
    "assets": ([("Amazon S3", "", "storage")], None),
    "m": ([("nginx", "1.24.0", "web-server")], None),
    "partners": ([("nginx", "1.24.0", "web-server")], None),
    "ftp": ([], None),
    "git": ([("GitLab", "15.0", "devops")], None),
    "analytics": ([], None),
    "beta": ([("nginx", "1.24.0", "web-server")], None),
}
for number in range(1, 15):
    HOSTS[f"store{number:02d}"] = ([("nginx", "1.24.0", "web-server")], None)

T, S = Finding.FindingType, Finding.Severity

# (host, type, severity, title, description, raw_data, age_days, state)
# state: open | overdue-ok (age decides) | resolved:<days ago> | accepted | false_positive
ISSUES = [
    ("db-backup", T.EXPOSED_FILE, S.CRITICAL, "Database dump is publicly downloadable",
     "https://db-backup.acme-retail.example/backup.sql returns a real database dump to anyone who asks for it.",
     {"check": "database_dump_exposed", "path": "/backup.sql"}, 3, "open"),
    ("legacy", T.EXPIRED_SSL, S.CRITICAL, "TLS certificate expired 12 days ago",
     "Certificate for legacy.acme-retail.example was valid until 12 days ago.",
     {"days_remaining": -12, "not_after": "-12"}, 12, "open"),
    ("staging", T.EXPOSED_FILE, S.CRITICAL, "Environment file (.env) is publicly downloadable",
     "https://staging.acme-retail.example/.env returns a real environment file (.env) to anyone who asks for it.",
     {"check": "env_exposed", "path": "/.env"}, 2, "open"),
    ("staging", T.OPEN_PORT, S.HIGH, "Open port 3389/tcp (ms-wbt-server)",
     "Port 3389/tcp is open, service: ms-wbt-server", {"port": "3389", "protocol": "tcp", "service": "ms-wbt-server"}, 41, "open"),
    ("dev", T.OPEN_PORT, S.HIGH, "Open port 5432/tcp (postgresql)",
     "Port 5432/tcp is open, service: postgresql", {"port": "5432", "protocol": "tcp", "service": "postgresql"}, 36, "open"),
    ("api", T.CORS, S.HIGH, "Any website can read logged-in users' data (CORS)",
     "api.acme-retail.example approves cross-site requests from any origin and allows cookies with them.",
     {"check": "cors_any_origin_with_credentials", "allow_credentials": True}, 9, "open"),
    ("promo2023", T.SUBDOMAIN_TAKEOVER, S.HIGH, "Subdomain points at an unclaimed Heroku address",
     "promo2023.acme-retail.example is a CNAME to acme-promo-2023.herokuapp.com, but nothing is hosted there any more.",
     {"check": "takeover", "provider": "Heroku", "cname": "acme-promo-2023.herokuapp.com"}, 18, "open"),
    ("", T.EMAIL_SECURITY, S.HIGH, "DMARC policy is monitor-only for acme-retail.example",
     "The DMARC policy is 'p=none': forged messages are reported but still delivered.",
     {"check": "dmarc_monitor_only", "domain": DOMAIN}, 64, "open"),
    ("shop", T.NUCLEI_MATCH, S.HIGH, "WordPress Login Panel Exposed",
     "A WordPress administrator login page is reachable from the internet.",
     {"template_id": "wordpress-login", "matched_at": "https://shop.acme-retail.example/wp-login.php"}, 22, "open"),
    ("legacy", T.WEAK_TLS, S.HIGH, "Server does not support TLS 1.2 or 1.3",
     "legacy.acme-retail.example only offers retired TLS versions.",
     {"check": "no_modern_protocol", "accepted_versions": ["TLS 1.0", "TLS 1.1"]}, 52, "open"),
    ("shop", T.OUTDATED_SOFTWARE, S.MEDIUM, "PHP 7.4.33 is out of support",
     "shop.acme-retail.example reports running PHP 7.4.33; PHP 8.1 and earlier no longer receive security fixes.",
     {"check": "end_of_life", "product": "PHP", "version": "7.4.33"}, 70, "open"),
    ("shop", T.OUTDATED_SOFTWARE, S.MEDIUM, "Apache HTTP Server 2.2.15 is out of support",
     "shop.acme-retail.example reports running Apache HTTP Server 2.2.15.",
     {"check": "end_of_life", "product": "Apache HTTP Server", "version": "2.2.15"}, 70, "open"),
    ("api-v1", T.OUTDATED_SOFTWARE, S.MEDIUM, "Microsoft IIS 8.5 is out of support",
     "api-v1.acme-retail.example reports running Microsoft IIS 8.5.",
     {"check": "end_of_life", "product": "Microsoft IIS", "version": "8.5"}, 95, "open"),
    ("checkout", T.MISSING_HEADER, S.MEDIUM, "Missing security header: CSP",
     "checkout.acme-retail.example does not set the Content-Security-Policy header.",
     {"header": "Content-Security-Policy"}, 30, "open"),
    ("www", T.MISSING_HEADER, S.MEDIUM, "Missing security header: HSTS",
     "www.acme-retail.example does not set the Strict-Transport-Security header.",
     {"header": "Strict-Transport-Security"}, 100, "open"),
    ("sso", T.INSECURE_COOKIE, S.MEDIUM, "Cookie 'SESSIONID' is missing HttpOnly, SameSite",
     "sso.acme-retail.example sets the cookie 'SESSIONID' without the HttpOnly, SameSite flags.",
     {"check": "session_cookie_flags", "cookie": "SESSIONID", "missing": ["HttpOnly", "SameSite"]}, 15, "open"),
    ("partners", T.NO_HTTPS, S.MEDIUM, "Site does not redirect HTTP to HTTPS",
     "partners.acme-retail.example serves content over plain HTTP (status 200).",
     {"check": "no_https_redirect", "http_status": 200}, 44, "open"),
    ("intranet", T.WEAK_TLS, S.MEDIUM, "Server still accepts TLS 1.0 and TLS 1.1",
     "intranet.acme-retail.example accepts connections using TLS 1.0 and TLS 1.1.",
     {"check": "old_protocol", "accepted_versions": ["TLS 1.0", "TLS 1.1", "TLS 1.2"]}, 60, "open"),
    ("grafana", T.EXPOSED_FILE, S.MEDIUM, "Apache server-status page is publicly downloadable",
     "https://grafana.acme-retail.example/server-status returns a real apache server-status page.",
     {"check": "server_status_exposed", "path": "/server-status"}, 26, "open"),
    ("www", T.EXPIRED_SSL, S.MEDIUM, "TLS certificate expires in 19 days",
     "Certificate for www.acme-retail.example expires in 19 days.",
     {"days_remaining": 19, "not_after": "19"}, 4, "open"),
    ("blog", T.MISSING_HEADER, S.LOW, "Missing security header: X-Frame-Options",
     "blog.acme-retail.example does not set the X-Frame-Options header.", {"header": "X-Frame-Options"}, 33, "open"),
    ("vpn", T.OPEN_PORT, S.LOW, "Open port 22/tcp (ssh)", "Port 22/tcp is open, service: ssh",
     {"port": "22", "protocol": "tcp", "service": "ssh"}, 120, "open"),
    ("mail", T.OPEN_PORT, S.LOW, "Open port 25/tcp (smtp)", "Port 25/tcp is open, service: smtp",
     {"port": "25", "protocol": "tcp", "service": "smtp"}, 120, "open"),
    ("ftp", T.OPEN_PORT, S.LOW, "Open port 21/tcp (ftp)", "Port 21/tcp is open, service: ftp",
     {"port": "21", "protocol": "tcp", "service": "ftp"}, 90, "accepted"),
    ("", T.SECURITY_TXT, S.LOW, "No security.txt on acme-retail.example",
     "acme-retail.example does not publish a security.txt file.", {"check": "security_txt_missing", "domain": DOMAIN}, 64, "open"),
    ("", T.EMAIL_SECURITY, S.INFO, "DKIM signing could not be confirmed for acme-retail.example",
     "No DKIM key was found under the selector names commonly used by mail providers.",
     {"check": "dkim_not_found", "domain": DOMAIN}, 64, "false_positive"),
    ("m", T.MISSING_HEADER, S.INFO, "Missing security header: Referrer-Policy",
     "m.acme-retail.example does not set the Referrer-Policy header.", {"header": "Referrer-Policy"}, 50, "open"),
    # Lookalike domains: someone else's registrations, imitating ours.
    ("", T.LOOKALIKE_DOMAIN, S.MEDIUM, "Lookalike domain registered: acmeretail.example",
     "acmeretail.example imitates acme-retail.example (hyphen removed) and can send and receive email.",
     {"check": "lookalike_mail", "domain": "acmeretail.example", "technique": "hyphen removed",
      "addresses": ["198.51.100.23"], "mail_servers": ["mx.acmeretail.example"]}, 6, "open"),
    ("", T.LOOKALIKE_DOMAIN, S.MEDIUM, "Lookalike domain registered: acme-retail-login.example",
     "acme-retail-login.example imitates acme-retail.example (added word) and can send and receive email.",
     {"check": "lookalike_mail", "domain": "acme-retail-login.example", "technique": "added word",
      "addresses": ["198.51.100.87"], "mail_servers": ["mail.acme-retail-login.example"]}, 2, "open"),
    ("", T.LOOKALIKE_DOMAIN, S.LOW, "Lookalike domain registered: acme-retai1.example",
     "acme-retai1.example imitates acme-retail.example (look-alike character) and points to a server.",
     {"check": "lookalike_web", "domain": "acme-retai1.example", "technique": "look-alike character",
      "addresses": ["203.0.113.140"], "mail_servers": []}, 30, "open"),
    # Fixed over the last weeks -- this is what makes the trend go up.
    ("api", T.OPEN_PORT, S.CRITICAL, "Open port 6379/tcp (redis)", "Port 6379/tcp is open, service: redis",
     {"port": "6379", "protocol": "tcp", "service": "redis"}, 80, "resolved:58"),
    ("git", T.EXPOSED_FILE, S.CRITICAL, "Git repository is publicly downloadable",
     "https://git.acme-retail.example/.git/HEAD returns a real git repository.",
     {"check": "git_exposed", "path": "/.git/HEAD"}, 75, "resolved:52"),
    ("assets", T.SUBDOMAIN_TAKEOVER, S.HIGH, "Subdomain points at an unclaimed Amazon S3 address",
     "assets.acme-retail.example is a CNAME to an S3 bucket that no longer exists.",
     {"check": "takeover", "provider": "Amazon S3"}, 70, "resolved:44"),
    ("", T.EMAIL_SECURITY, S.HIGH, "No SPF record for acme-retail.example",
     "The domain publishes no SPF record.", {"check": "spf_missing", "domain": DOMAIN}, 88, "resolved:37"),
    ("pay", T.WEAK_TLS, S.MEDIUM, "Server still accepts TLS 1.0 and TLS 1.1",
     "pay.acme-retail.example accepts connections using TLS 1.0 and TLS 1.1.",
     {"check": "old_protocol"}, 60, "resolved:30"),
    ("uploads", T.CORS, S.MEDIUM, "CORS trusts the 'null' origin with credentials",
     "uploads.acme-retail.example allows credentialed cross-site requests from the 'null' origin.",
     {"check": "cors_null_origin_with_credentials"}, 50, "resolved:21"),
    ("careers", T.NO_HTTPS, S.HIGH, "Site is only available over unencrypted HTTP",
     "careers.acme-retail.example answers on plain HTTP and does not offer HTTPS at all.",
     {"check": "http_only"}, 40, "resolved:14"),
    ("beta", T.INSECURE_COOKIE, S.MEDIUM, "Cookie 'auth_token' is missing Secure",
     "beta.acme-retail.example sets the cookie 'auth_token' without the Secure flag.",
     {"check": "session_cookie_flags", "cookie": "auth_token", "missing": ["Secure"]}, 25, "resolved:6"),
    ("checkout", T.MISSING_HEADER, S.MEDIUM, "Missing security header: HSTS",
     "checkout.acme-retail.example does not set the Strict-Transport-Security header.",
     {"header": "Strict-Transport-Security"}, 30, "resolved:3"),
]

# Who has been asked to fix what (host, title prefix) -> member.
ASSIGNMENTS = {
    ("db-backup", "Database dump"): "brian",
    ("legacy", "TLS certificate expired"): "amina",
    ("staging", "Open port 3389"): "brian",
    ("dev", "Open port 5432"): "brian",
    ("", "DMARC policy"): "owner",
    ("shop", "PHP 7.4.33"): "amina",
    ("www", "Missing security header: HSTS"): "owner",
    ("api", "Any website can read"): "owner",
    ("", "Lookalike domain registered: acmeretail"): "owner",
}

# host -> (importance, labels)
CONTEXT = {
    "pay": (Asset.Criticality.CROWN_JEWEL, ["payments", "customer-facing"]),
    "checkout": (Asset.Criticality.CROWN_JEWEL, ["payments", "customer-facing"]),
    "shop": (Asset.Criticality.CROWN_JEWEL, ["customer-facing"]),
    "sso": (Asset.Criticality.CROWN_JEWEL, ["identity"]),
    "db-backup": (Asset.Criticality.HIGH, ["data"]),
    "api": (Asset.Criticality.HIGH, ["customer-facing"]),
    "www": (Asset.Criticality.HIGH, ["customer-facing"]),
    "mail": (Asset.Criticality.HIGH, []),
    "staging": (Asset.Criticality.LOW, ["non-production"]),
    "dev": (Asset.Criticality.LOW, ["non-production"]),
    "beta": (Asset.Criticality.LOW, ["non-production"]),
    "legacy": (Asset.Criticality.NORMAL, ["legacy"]),
    "api-v1": (Asset.Criticality.NORMAL, ["legacy"]),
    "blog": (Asset.Criticality.LOW, ["marketing"]),
    "promo2023": (Asset.Criticality.LOW, ["marketing"]),
    "support": (Asset.Criticality.NORMAL, ["third-party"]),
    "status": (Asset.Criticality.NORMAL, ["third-party"]),
    "careers": (Asset.Criticality.LOW, ["third-party"]),
}
# Run by suppliers on their own platforms: never scanned.
OUT_OF_SCOPE = [f"support.{DOMAIN}", f"status.{DOMAIN}", f"careers.{DOMAIN}"]
# Healthy certificates (days left) and web ports, as the scanners record them.
CERTIFICATES = {"": 64, "shop": 41, "checkout": 77, "api": 33, "sso": 52, "pay": 85, "blog": 120,
                "docs": 210, "m": 64, "partners": 158, "grafana": 47, "intranet": 301}
WEB_PORTS = ["", "www", "shop", "checkout", "api", "sso", "pay", "partners"]

# (host, title prefix) -> [(days ago, who, text)]
COMMENTS = {
    ("db-backup", "Database dump"): [
        (2, "brian", "Confirmed: it's last month's migration dump. Removing it and rotating the database "
                     "password today."),
        (1, "amina", "Thanks. Before you delete it, check the web server logs for downloads of backup.sql "
                     "so we know whether this needs to be reported."),
        (0, "brian", "Logs show two downloads from an unknown address on Tuesday. Opened incident INC-2291."),
    ],
    ("legacy", "TLS certificate expired"): [
        (6, "amina", "Renewal is waiting on the hosting vendor. They've promised it by Friday."),
    ],
    ("dev", "Open port 5432"): [
        (8, "brian", "This was closed in September. Looks like the firewall rule was lost when the dev "
                     "server was rebuilt."),
    ],
}

PEOPLE = [("amina", "Amina Otieno", Membership.Role.ADMIN), ("brian", "Brian Mwangi", Membership.Role.ANALYST),
          ("chloe", "Chloe Wanjiru", Membership.Role.VIEWER)]


class Command(BaseCommand):
    help = "Load a fictional demo organization (Acme Retail) with three months of realistic history."

    def add_arguments(self, parser):
        parser.add_argument("--owner", required=True, help="Username that will own the demo organization.")
        parser.add_argument("--reset", action="store_true", help="Delete an existing demo organization first.")

    def handle(self, *args, **options):
        User = get_user_model()
        owner = User.objects.filter(username=options["owner"]).first()
        if owner is None:
            raise CommandError(f"No user called '{options['owner']}'. Create one with createsuperuser first.")

        existing = Organization.objects.filter(root_domain=DOMAIN).first()
        if existing:
            if not options["reset"]:
                raise CommandError(f"{NAME} is already loaded. Use --reset to replace it.")
            delete_organization(existing)

        rng = random.Random(2026)
        now = timezone.now()
        with transaction.atomic():
            organization = Organization.objects.create(
                name=NAME, root_domain=DOMAIN, domain_verified_at=now - timedelta(days=95)
            )
            Organization.objects.filter(id=organization.id).update(created_at=now - timedelta(days=95))
            Membership.objects.create(user=owner, organization=organization, role=Membership.Role.OWNER)
            people = {"owner": owner}
            for username, full_name, role in PEOPLE:
                first, last = full_name.split()
                person, created = User.objects.get_or_create(
                    username=username,
                    defaults={"first_name": first, "last_name": last, "email": f"{username}@{DOMAIN}"},
                )
                if created:
                    person.set_unusable_password()  # demo colleagues can't log in
                    person.save()
                Membership.objects.get_or_create(user=person, organization=organization, defaults={"role": role})
                people[username] = person

            assets = self._assets(organization, now, rng)
            self._issues(organization, assets, people, now)
            self._inventory(assets, now)
            self._context(organization, assets, people, now)
            self._scan_history(organization, assets, now, rng)
            self._rules(organization)
            self._activity(organization, people, now)
            self._trend(organization, now, rng)

        self.stdout.write(self.style.SUCCESS(
            f"Loaded {NAME} ({DOMAIN}) with {len(assets)} assets, owned by {owner.username}. "
            "Select it from the organization switcher."
        ))

    # ------------------------------------------------------------------

    def _assets(self, organization, now, rng):
        assets = {}
        for host, (technologies, _image) in HOSTS.items():
            value = f"{host}.{DOMAIN}" if host else DOMAIN
            asset = Asset.objects.create(
                organization=organization, value=value,
                asset_type=Asset.AssetType.DOMAIN if not host else Asset.AssetType.SUBDOMAIN,
                source=Asset.Source.MANUAL if host in ("vpn", "intranet") else Asset.Source.DISCOVERED,
            )
            age = 4 if host in ("db-backup", "promo2023") else rng.randint(20, 95)
            Asset.objects.filter(id=asset.id).update(first_seen=now - timedelta(days=age), last_seen=now)
            for name, version, category in technologies:
                Technology.objects.create(asset=asset, name=name, version=version, category=category)
            assets[host] = asset
        return assets

    def _issues(self, organization, assets, people, now):
        for host, kind, severity, title, description, raw, age, state in ISSUES:
            if "not_after" in raw:
                raw = {**raw, "not_after": (now + timedelta(days=int(raw["not_after"]))).isoformat()}
            fields = dict(
                asset=assets[host], finding_type=kind, severity=severity, title=title,
                description=description, raw_data=raw,
                dedupe_key=Finding.build_dedupe_key(kind, f"{host}:{title}"),
            )
            if state.startswith("resolved:"):
                fields.update(is_active=False, resolved_at=now - timedelta(days=int(state.split(":")[1])))
            elif state in ("accepted", "false_positive"):
                fields.update(
                    status=state, status_changed_by=people["amina"], status_changed_at=now - timedelta(days=5),
                    status_note=(
                        "Partner upload server; restricted to their IP range."
                        if state == "accepted" else "Our mail provider signs with a custom selector."
                    ),
                )
            assignee = next(
                (people[who] for (h, prefix), who in ASSIGNMENTS.items() if h == host and title.startswith(prefix)),
                None,
            )
            finding = Finding.objects.create(assignee=assignee, **fields)
            Finding.objects.filter(id=finding.id).update(first_seen=now - timedelta(days=age))

    def _inventory(self, assets, now):
        screenshots = Path(settings.MEDIA_ROOT) / "screenshots"
        for host, asset in assets.items():
            Finding.objects.create(
                asset=asset, finding_type=T.SUBDOMAIN_DISCOVERED, severity=S.INFO,
                title=f"Subdomain discovered: {asset.value}", raw_data={"subdomain": asset.value},
                dedupe_key=Finding.build_dedupe_key(T.SUBDOMAIN_DISCOVERED, "discovered"),
            )
            image = HOSTS[host][1]
            if image and (DEMO_ASSETS / f"{image}.png").exists():
                relative = f"screenshots/{asset.id}/demo-{image}.png"
                (screenshots / str(asset.id)).mkdir(parents=True, exist_ok=True)
                shutil.copy(DEMO_ASSETS / f"{image}.png", Path(settings.MEDIA_ROOT) / relative)
                title = {"www": "Acme Retail · The autumn edit", "shop": "Checkout · Acme Retail",
                         "sso": "Staff sign-in · Acme Retail", "staging": "Staging · build 4.12.0-rc3",
                         "grafana": "Grafana", "status": "Acme Retail Status"}[image]
                Finding.objects.create(
                    asset=asset, finding_type=T.SCREENSHOT, severity=S.INFO,
                    title=f"Screenshot captured: {title}",
                    raw_data={"screenshot_path": relative, "page_title": title, "final_url": f"https://{asset.value}/"},
                    dedupe_key=Finding.build_dedupe_key(T.SCREENSHOT, "latest"),
                )
        for record_type, value in [("A", "203.0.113.24"), ("MX", "10 mail.acme-retail.example."), ("NS", "ns1.dns-host.example.")]:
            Finding.objects.create(
                asset=assets[""], finding_type=T.DNS_CHANGE, severity=S.INFO, title=f"{record_type} record: {value}",
                raw_data={"record_type": record_type, "value": value},
                dedupe_key=Finding.build_dedupe_key(T.DNS_CHANGE, f"{record_type}:{value}"),
            )

    def _context(self, organization, assets, people, now):
        """What people add on top of the scans: importance, scope, discussion."""
        for host, (criticality, tags) in CONTEXT.items():
            Asset.objects.filter(id=assets[host].id).update(criticality=criticality, tags=tags)
        organization.scope_exclusions = OUT_OF_SCOPE
        organization.save(update_fields=["scope_exclusions"])

        for host, days_left in CERTIFICATES.items():
            asset = assets[host]
            finding = Finding.objects.create(
                asset=asset, finding_type=T.EXPIRED_SSL, severity=S.INFO,
                title=f"TLS certificate expires in {days_left} days",
                description=f"Certificate for {asset.value} is valid for another {days_left} days.",
                raw_data={"days_remaining": days_left, "not_after": (now + timedelta(days=days_left)).isoformat()},
                dedupe_key=Finding.build_dedupe_key(T.EXPIRED_SSL, "cert_expiry"),
            )
            Finding.objects.filter(id=finding.id).update(first_seen=now - timedelta(days=60))
        for host in WEB_PORTS:
            Finding.objects.create(
                asset=assets[host], finding_type=T.OPEN_PORT, severity=S.INFO,
                title="Open port 443/tcp (https)", description="Port 443/tcp is open, service: https",
                raw_data={"port": "443", "protocol": "tcp", "service": "https", "product": "nginx"},
                dedupe_key=Finding.build_dedupe_key(T.OPEN_PORT, "443/tcp"),
            )

        def issue(host, prefix):
            return Finding.objects.get(asset=assets[host], title__startswith=prefix)

        V = ActivityEvent.Verb
        for (host, prefix), comments in COMMENTS.items():
            finding = issue(host, prefix)
            for days_ago, who, body in comments:
                comment = FindingComment.objects.create(
                    finding=finding, author=people[who], author_name=who, body=body
                )
                FindingComment.objects.filter(id=comment.id).update(created_at=now - timedelta(days=days_ago, hours=1))

        # A fix that didn't stick: the database port was closed, then came back.
        came_back = issue("dev", "Open port 5432")
        Finding.objects.filter(id=came_back.id).update(reopened_count=1, reopened_at=now - timedelta(days=8))
        event = ActivityEvent.objects.create(
            organization=organization, finding=came_back, actor_name="System", verb=V.FINDING_REOPENED,
            summary=f"'{came_back.title}' on {came_back.asset.value} came back after being fixed",
        )
        ActivityEvent.objects.filter(id=event.id).update(created_at=now - timedelta(days=8, hours=5))

        # An acceptance with an end date: someone has to look again in six weeks.
        Finding.objects.filter(asset=assets["ftp"], status=Finding.Status.ACCEPTED).update(
            accepted_until=timezone.localdate() + timedelta(days=45)
        )

    def _scan_history(self, organization, assets, now, rng):
        jobs = []
        for days_ago in (7, 1):
            for name in list_scanners():
                batch = uuid.uuid4()
                started = now - timedelta(days=days_ago, hours=rng.randint(1, 5))
                targets = [None] if get_scanner(name).applies_to == "organization" else list(assets.values())
                for asset in targets:
                    failed = rng.random() < 0.03
                    jobs.append(ScanJob(
                        organization=organization, asset=asset, scanner_name=name, batch_id=batch,
                        status=ScanJob.Status.FAILED if failed else ScanJob.Status.SUCCESS,
                        error_message="Connection timed out" if failed else "",
                        idempotency_key=uuid.uuid4().hex, started_at=started,
                        finished_at=started + timedelta(seconds=rng.randint(4, 300)),
                    ))
        ScanJob.objects.bulk_create(jobs)
        for job in ScanJob.objects.filter(organization=organization):
            ScanJob.objects.filter(id=job.id).update(created_at=job.started_at)

    def _rules(self, organization):
        NotificationRule.objects.create(
            organization=organization, recipient_email=f"security@{DOMAIN}", min_severity=S.HIGH, weekly_report=True
        )
        NotificationRule.objects.create(
            organization=organization, recipient_email=f"cto@{DOMAIN}", min_severity=S.CRITICAL, weekly_report=True
        )
        NotificationRule.objects.create(
            organization=organization, channel=NotificationRule.Channel.WEBHOOK,
            webhook_url="https://hooks.slack.com/services/T00000000/B00000000/demo", min_severity=S.HIGH,
        )

    def _activity(self, organization, people, now):
        V = ActivityEvent.Verb
        timeline = [
            (95, "owner", V.ORG_CREATED, f"Created {NAME} for {DOMAIN}"),
            (95, "owner", V.DOMAIN_VERIFIED, f"Verified ownership of {DOMAIN}"),
            (94, "owner", V.MEMBER_ADDED, "Added amina as Admin"),
            (94, "owner", V.MEMBER_ADDED, "Added brian as Security Analyst"),
            (90, "amina", V.RULE_CREATED, f"Added an email rule for security@{DOMAIN}"),
            (60, "amina", V.MEMBER_ADDED, "Added chloe as Viewer"),
            (58, "brian", V.SCAN_STARTED, "Started Port scan on all 46 assets"),
            (40, "amina", V.RULE_CREATED, "Added a webhook rule for the #security Slack channel"),
            (12, "brian", V.SCAN_STARTED, "Started Exposed sensitive files on all 46 assets"),
            (30, "amina", V.SCOPE_CHANGED, "Set the hosts never to scan to: " + ", ".join(OUT_OF_SCOPE)),
            (29, "amina", V.ASSET_UPDATED, f"Set pay.{DOMAIN}'s importance crown jewel and labels payments, customer-facing"),
            (7, "amina", V.FINDING_ASSIGNED, f"Assigned 'DMARC policy is monitor-only' on {DOMAIN} to {{owner}}",
             ("", "DMARC policy")),
            (6, "amina", V.FINDING_COMMENTED, f"Commented on 'TLS certificate expired 12 days ago' on legacy.{DOMAIN}",
             ("legacy", "TLS certificate expired")),
            (5, "amina", V.FINDING_TRIAGED,
             f"Marked 'Open port 21/tcp (ftp)' on ftp.{DOMAIN} as risk accepted until "
             + (timezone.localdate() + timedelta(days=45)).isoformat(), ("ftp", "Open port 21")),
            (5, "amina", V.FINDING_TRIAGED,
             f"Marked 'DKIM signing could not be confirmed' on {DOMAIN} as false positive", ("", "DKIM signing")),
            (2, "brian", V.FINDING_ASSIGNED, f"Assigned 'Database dump is publicly downloadable' on db-backup.{DOMAIN} to brian",
             ("db-backup", "Database dump")),
            (2, "brian", V.FINDING_COMMENTED, f"Commented on 'Database dump is publicly downloadable' on db-backup.{DOMAIN}",
             ("db-backup", "Database dump")),
            (2, "owner", V.REPORT_DOWNLOADED, "Downloaded the PDF report"),
            (1, "brian", V.SCAN_STARTED, "Started Subdomain discovery on acme-retail.example"),
        ]
        for days_ago, who, verb, summary, *about in timeline:
            finding = None
            if about:
                host, prefix = about[0]
                value = f"{host}.{DOMAIN}" if host else DOMAIN
                finding = Finding.objects.get(asset__organization=organization, asset__value=value,
                                              title__startswith=prefix)
            event = ActivityEvent.objects.create(
                organization=organization, actor=people[who], actor_name=people[who].username, verb=verb,
                summary=summary.replace("{owner}", people["owner"].username), finding=finding,
            )
            ActivityEvent.objects.filter(id=event.id).update(created_at=now - timedelta(days=days_ago, hours=3))

    def _trend(self, organization, now, rng):
        """
        Ninety days of history ending at today's real numbers: a rough
        start, steady improvement as issues were fixed, and a dip this
        week when new problems turned up.
        """
        today = record_snapshot(organization, build_risk_summary(organization))
        end = today.score or 70
        for days_ago in range(90, 0, -1):
            progress = (90 - days_ago) / 90
            score = 41 + (end + 9 - 41) * progress  # climbs to above today's score...
            if days_ago <= 4:
                score = end + days_ago * 2  # ...then dips as this week's issues appear
            score = round(max(0, min(100, score + rng.uniform(-1.8, 1.8))), 1)
            grade = next(g for threshold, g in [(95, "A+"), (85, "A"), (70, "B"), (50, "C"), (30, "D"), (0, "F")] if score >= threshold)
            RiskSnapshot.objects.update_or_create(
                organization=organization, date=timezone.localdate() - timedelta(days=days_ago),
                defaults=dict(
                    score=score, grade=grade, asset_count=len(HOSTS), assets_at_risk=max(6, round(30 - 20 * progress)),
                    open_issues=max(18, round(48 - 26 * progress)), critical_high=max(5, round(14 - 9 * progress)),
                ),
            )
