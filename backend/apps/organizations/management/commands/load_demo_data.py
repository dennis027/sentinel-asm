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
from apps.findings import kev
from apps.logs.detections import analyze, check_silent_sources
from apps.logs.ingest import store
from apps.logs.models import ErrorGroup, LogAlertRule, LogSource
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
    ("checkout", T.EXPOSED_SECRET, S.CRITICAL, "Stripe secret key in public JavaScript (checkout.3f9a1c.js)",
     "https://checkout.acme-retail.example/static/js/checkout.3f9a1c.js contains what looks like a Stripe secret key "
     "(sk_liv…Q2xd). Anyone visiting the site can read it. Roll the key in the Stripe dashboard; it can create charges "
     "and refunds. Then remove it from the front-end code and keep it on the server.",
     {"check": "exposed_secret", "kind": "stripe_secret", "masked": "sk_liv…Q2xd",
      "file": "https://checkout.acme-retail.example/static/js/checkout.3f9a1c.js"}, 3, "open"),
    ("", T.PUBLIC_BUCKET, S.HIGH, "Public Amazon S3 bucket: acme-retail-backups",
     "Anyone can list the files in the Amazon S3 bucket \"acme-retail-backups\" "
     "(https://acme-retail-backups.s3.amazonaws.com/). Files listed: orders-2026-09.csv.gz, "
     "customers-export.xlsx, db/shop-2026-10-01.sql.gz. Confirm it belongs to you; if it does, block public access.",
     {"check": "public_bucket", "provider": "s3", "bucket": "acme-retail-backups",
      "url": "https://acme-retail-backups.s3.amazonaws.com/",
      "sample_objects": ["orders-2026-09.csv.gz", "customers-export.xlsx", "db/shop-2026-10-01.sql.gz"]}, 6, "open"),
    ("", T.DOMAIN_REGISTRATION, S.HIGH, "acme-retail.example expires in 23 day(s)",
     "The registration of acme-retail.example ends in 23 days (registrar: Example Registrar). When it lapses the "
     "website and email stop working, and after a grace period anyone can register it.",
     {"check": "domain_expiring", "days_remaining": 23, "registrar": "Example Registrar"}, 1, "open"),
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
            self._scan_history(organization, assets, people, now, rng)
            self._rules(organization)
            self._activity(organization, people, now)
            self._known_exploited(assets, now)
            self._server_logs(organization, people, now, rng)
            self._app_logs(organization, people, now, rng)
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
            if raw.get("check") == "domain_expiring":
                raw = {**raw, "expires": (now + timedelta(days=raw["days_remaining"])).isoformat()}
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

    def _scan_history(self, organization, assets, people, now, rng):
        """
        Where scans came from: the nightly schedule twice, Amina running a
        port scan over every host, and Brian re-checking the shop after
        a fix.
        """
        T = ScanJob.Trigger
        jobs = []

        def add(name, asset, started, trigger, run_id, who=None, batch=None, fail_rate=0.03):
            failed = rng.random() < fail_rate
            jobs.append(ScanJob(
                organization=organization, asset=asset, scanner_name=name, batch_id=batch,
                trigger=trigger, run_id=run_id, triggered_by=who,
                status=ScanJob.Status.FAILED if failed else ScanJob.Status.SUCCESS,
                error_message="Connection timed out" if failed else "",
                idempotency_key=uuid.uuid4().hex, started_at=started,
                finished_at=started + timedelta(seconds=rng.randint(4, 300)),
            ))

        for days_ago in (7, 1):
            night = (now - timedelta(days=days_ago)).replace(hour=2, minute=0, second=0, microsecond=0)
            run = ScanJob.schedule_run_id(organization.id, night.date())
            for name in list_scanners():
                targets = [None] if get_scanner(name).applies_to == "organization" else list(assets.values())
                for asset in targets:
                    add(name, asset, night + timedelta(seconds=rng.randint(0, 900)), T.SCHEDULE, run)

        batch = uuid.uuid4()
        started = now - timedelta(days=3, hours=4)
        for asset in assets.values():
            add("nmap", asset, started + timedelta(seconds=rng.randint(0, 240)), T.DOMAIN, batch, people["amina"], batch)

        recheck = uuid.uuid4()
        started = now - timedelta(days=2, hours=6)
        for name in list_scanners():
            if get_scanner(name).applies_to != "organization":
                add(name, assets["shop"], started + timedelta(seconds=rng.randint(0, 60)), T.RECHECK, recheck,
                    people["brian"], fail_rate=0)

        add("ssl_expiry", assets["www"], now - timedelta(hours=5), T.SINGLE, uuid.uuid4(), people["amina"], fail_rate=0)
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

    def _server_logs(self, organization, people, now, rng):
        """
        Four connected servers and two days of their logs, fed through the
        real parser and detections: an SSH brute force that ends in a
        successful sign-in, a new admin account, a password spray, an RDP
        brute force with a lockout, a new service, and a server gone quiet.
        """
        def journald(minutes_ago, host, program, message):
            return {"date": (now - timedelta(minutes=minutes_ago)).timestamp(), "_HOSTNAME": host,
                    "SYSLOG_IDENTIFIER": program, "PRIORITY": "6", "MESSAGE": message}

        def windows(minutes_ago, host, event_id, inserts=(), message="", channel="Security"):
            return {"EventID": event_id, "Channel": channel, "Computer": host, "Level": 0,
                    "TimeCreated": (now - timedelta(minutes=minutes_ago)).isoformat(),
                    "StringInserts": list(inserts), "Message": message}

        def logon(minutes_ago, host, event_id, user, ip, logon_type="10"):
            inserts = ["S-1-0-0", "-", "-", "0x0", "S-1-5-21", user, "ACME", "0x0", logon_type, "User32",
                       "Negotiate", "WS-17", "-", "-", "0", "0x0", "-", "-", ip, "3389"]
            if event_id == 4625:
                inserts = inserts[:7] + ["0xc000006d", "%%2313", "0xc000006a", logon_type] + inserts[9:] + ["51515"]
                inserts[19] = ip
            return windows(minutes_ago, host, event_id, inserts)

        office, attacker, sprayer, rdp_attacker = "198.51.100.10", "203.0.113.77", "198.51.100.200", "192.0.2.66"
        servers = {
            "web-01": LogSource.OS.LINUX, "db-01": LogSource.OS.LINUX,
            "dc-01": LogSource.OS.WINDOWS, "files-01": LogSource.OS.WINDOWS,
        }
        records = {name: [] for name in servers}

        # Two days of ordinary activity on every server.
        for minutes_ago in range(2880, 0, -rng.randint(18, 30)):
            records["web-01"].append(journald(minutes_ago, "web-01", "CRON", "pam_unix(cron:session): session opened for user root(uid=0)"))
            records["db-01"].append(journald(minutes_ago - 3, "db-01", "systemd", "Started Daily apt download activities."))
            records["dc-01"].append(logon(minutes_ago - 5, "DC-01", 4624, rng.choice(["amina", "brian", "svc_backup"]), office, "3"))
            if minutes_ago > 200:
                records["files-01"].append(logon(minutes_ago - 7, "FILES-01", 4624, "svc_backup", office, "3"))
        for minutes_ago in (2700, 1500, 300, 60):
            records["web-01"].append(journald(minutes_ago, "web-01", "sshd", f"Accepted publickey for deploy from {office} port 50222 ssh2"))
            records["db-01"].append(journald(minutes_ago + 4, "db-01", "sshd", f"Accepted publickey for amina from {office} port 50310 ssh2"))

        # web-01: a brute force last night that worked, then a new admin account.
        for i in range(42):
            records["web-01"].append(journald(1170 - i * 0.2, "web-01", "sshd",
                                              f"Failed password for deploy from {attacker} port {40000 + i} ssh2"))
        records["web-01"].append(journald(1161, "web-01", "sshd", f"Accepted password for deploy from {attacker} port 40999 ssh2"))
        records["web-01"].append(journald(1158, "web-01", "useradd", "new user: name=backup2, UID=1003, GID=1003, home=/home/backup2"))
        records["web-01"].append(journald(1157, "web-01", "usermod", "add 'backup2' to group 'sudo'"))
        records["web-01"].append(journald(1156, "web-01", "sudo", "deploy : TTY=pts/2 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt install -y netcat"))

        # db-01: one address trying many account names.
        for i, name in enumerate(["oracle", "postgres", "test", "admin", "ubuntu", "git", "ftp"] * 2):
            records["db-01"].append(journald(400 - i, "db-01", "sshd", f"Invalid user {name} from {sprayer} port {51000 + i}"))

        # dc-01: RDP guessing against one account until it locked, and a new service.
        for i in range(16):
            records["dc-01"].append(logon(95 - i * 0.3, "DC-01", 4625, "j.smith", rdp_attacker))
        records["dc-01"].append(windows(90, "DC-01", 4740, ["j.smith", "ACME", "S-1-5-21-1", "DC-01$"],
                                        "A user account was locked out."))
        records["dc-01"].append(windows(30, "DC-01", 7045, message="A service was installed in the system. "
                                        "Service Name: Remote Support Agent. Service File Name: C:\\Users\\Public\\rsa.exe",
                                        channel="System"))

        for name, os_name in servers.items():
            source = LogSource(organization=organization, name=name, os=os_name, created_by=people["owner"])
            source.issue_key()
            source.save()
            batch = sorted(records[name], key=lambda r: r.get("date") or r["TimeCreated"])
            # In chunks, as a shipper would send them.
            for start in range(0, len(batch), 40):
                analyze(source, store(source, batch[start:start + 40]))
            LogSource.objects.filter(id=source.id).update(created_at=now - timedelta(days=3))
        # files-01 last spoke over three hours ago.
        LogSource.objects.filter(organization=organization, name="files-01").update(last_seen_at=now - timedelta(minutes=200))
        check_silent_sources(now)

    def _known_exploited(self, assets, now):
        """
        One finding whose CVE is in CISA's Known Exploited Vulnerabilities
        catalogue, so it is flagged "exploited in the wild" and leads the
        fix plan. The catalogue entry is the real one (a full sync_kev
        adds the other ~1,400).
        """
        kev.load({"vulnerabilities": [{
            "cveID": "CVE-2023-4966", "vendorProject": "Citrix", "product": "NetScaler ADC and NetScaler Gateway",
            "vulnerabilityName": "Citrix NetScaler ADC and NetScaler Gateway Buffer Overflow Vulnerability",
            "dateAdded": "2023-10-18",
            "shortDescription": "Citrix NetScaler ADC and NetScaler Gateway contain a buffer overflow vulnerability "
                                "that allows for sensitive information disclosure when configured as a Gateway or "
                                "AAA virtual server.",
            "requiredAction": "Apply mitigations per vendor instructions or discontinue use of the product if "
                              "mitigations are unavailable.",
            "dueDate": "2023-11-08", "knownRansomwareCampaignUse": "Known",
        }]})
        title = "Citrix NetScaler session token leak (CVE-2023-4966, \"Citrix Bleed\")"
        finding = Finding.objects.create(
            asset=assets["vpn"], finding_type=Finding.FindingType.NUCLEI_MATCH, severity=Finding.Severity.HIGH,
            title=title,
            description="vpn.acme-retail.example answers like an unpatched NetScaler Gateway: an oversized Host "
                        "header returns memory that can contain other users' session tokens.",
            raw_data={"template_id": "CVE-2023-4966", "matched_at": "https://vpn.acme-retail.example/oauth/idp/.well-known/openid-configuration",
                      "info": {"classification": {"cve-id": ["cve-2023-4966"]}}},
            dedupe_key=Finding.build_dedupe_key(Finding.FindingType.NUCLEI_MATCH, f"vpn:{title}"),
        )
        Finding.objects.filter(id=finding.id).update(first_seen=now - timedelta(days=2))

    def _app_logs(self, organization, people, now, rng):
        """
        Two connected applications -- a Django shop backend and a Node.js
        payments service -- and a day of their logs through the same
        parser: grouped exceptions (one that came back after being
        resolved), a burst of 5xx, attack probes, a password logged by
        mistake, and password guessing against the app's login.
        """
        def at(minutes_ago):
            return (now - timedelta(minutes=minutes_ago)).timestamp()

        def django_request(minutes_ago, method, path, status, ip, user=None):
            return {"timestamp": at(minutes_ago), "level": "WARNING" if status >= 400 else "INFO",
                    "logger": "django.request", "service": "shop-api", "message": f"{method} {path} {status}",
                    "method": method, "path": path, "status": status, "ip": ip, **({"user": user} if user else {})}

        def python_error(minutes_ago, kind, value, frames, message, **extra):
            stack = "Traceback (most recent call last):\n" + "".join(
                f'  File "{file}", line {line}, in {func}\n    {code}\n' for file, line, func, code in frames
            ) + f"{kind}: {value}"
            return {"timestamp": at(minutes_ago), "level": "ERROR", "logger": "django.request", "service": "shop-api",
                    "message": message, "exception": {"type": kind, "value": value, "stacktrace": stack}, **extra}

        def pino(minutes_ago, level, msg, **fields):
            return {"time": int(at(minutes_ago) * 1000), "level": level, "pid": 41, "hostname": "payments-7f9c",
                    "service": "payments", "msg": msg, **fields}

        def node_error(minutes_ago, kind, message, frames, msg, **fields):
            stack = f"{kind}: {message}\n" + "\n".join(f"    at {func} ({file}:{line}:{col})" for func, file, line, col in frames)
            return pino(minutes_ago, 50, msg, err={"type": kind, "message": message, "stack": stack}, **fields)

        django_frames = [
            ("/usr/local/lib/python3.12/site-packages/django/core/handlers/base.py", 197, "_get_response",
             "response = wrapped_callback(request, *callback_args, **callback_kwargs)"),
            ("/srv/app/shop/orders/views.py", 88, "checkout", "line = cart.lines[item['sku']]"),
        ]
        stock_frames = [
            ("/usr/local/lib/python3.12/site-packages/django/db/models/query.py", 649, "get", "raise self.model.DoesNotExist("),
            ("/srv/app/shop/catalog/stock.py", 31, "reserve", "level = StockLevel.objects.get(sku=sku, store=store)"),
        ]
        email_frames = [("/srv/app/shop/notify/email.py", 54, "send_receipt", "smtp.sendmail(sender, [to], body)")]
        gateway_frames = [
            ("charge", "/srv/payments/src/gateway.js", 112, 19), ("async processPayment", "/srv/payments/src/routes/pay.js", 48, 5),
            ("node:internal/process/task_queues", "node:internal/process/task_queues", 95, 5),
        ]
        refund_frames = [("refund", "/srv/payments/src/refunds.js", 27, 31),
                         ("Layer.handle", "/srv/payments/node_modules/express/lib/router/layer.js", 95, 5)]

        office, customers = "198.51.100.10", [f"203.0.113.{n}" for n in range(20, 60)]
        prober, guesser = "192.0.2.150", "198.51.100.231"
        shop, payments = [], []

        # A day of ordinary traffic.
        for minutes_ago in range(1440, 0, -rng.randint(6, 12)):
            shop.append(django_request(minutes_ago, "GET", rng.choice(["/api/products/", "/api/cart/", "/api/products/42/"]),
                                       200, rng.choice(customers)))
            payments.append(pino(minutes_ago - 1, 30, "request completed",
                                 req={"method": "POST", "url": "/v1/charges", "remoteAddress": rng.choice(customers)},
                                 res={"statusCode": 201}, responseTime=rng.randint(80, 400)))

        # shop-api: a checkout bug since this morning's 2.15.0 deploy, a stock lookup that fails now and
        # then, one email outage.
        for minutes_ago in range(590, 0, -23):
            shop.append(python_error(minutes_ago, "KeyError", "'sku'", django_frames,
                                     "Internal Server Error: /api/checkout/", path="/api/checkout/", status=500))
        for minutes_ago in (1300, 900, 610, 240, 75):
            shop.append(python_error(minutes_ago, "DoesNotExist", "StockLevel matching query does not exist.", stock_frames,
                                     f"Could not reserve stock for order {rng.randint(10000, 99999)}"))
        shop.append(python_error(500, "SMTPServerDisconnected", "Connection unexpectedly closed", email_frames,
                                 "Receipt email failed for order 48211"))
        # A developer logged a whole login form, password included.
        shop.append({"timestamp": at(380), "level": "DEBUG", "logger": "shop.accounts", "service": "shop-api",
                     "message": "login form received: username=brian.k password=Summer2026! remember=on"})
        # Someone guessing passwords against the shop's own login.
        for i in range(30):
            shop.append(django_request(150 - i * 0.2, "POST", "/api/auth/login/", 401, guesser,
                                       user=rng.choice(["admin", "brian.k", "amina", "test"])))
        # A scanner probing for SQL injection and leftover files.
        for i, path in enumerate(["/api/products/?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
                                  "/.env", "/.git/config", "/phpmyadmin/", "/api/products/?q=../../../../etc/passwd",
                                  "/wp-admin/install.php", "/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                                  "/cgi-bin/luci"]):
            shop.append(django_request(65 - i * 0.5, "GET", path, 404, prober)
                        | {"user_agent": "sqlmap/1.8.2#stable (https://sqlmap.org)"})

        # payments: the card gateway timed out in a burst of 5xx twenty minutes ago.
        for i in range(36):
            payments.append(node_error(25 - i * 0.1, "GatewayTimeoutError", "upstream card gateway timed out after 10000ms",
                                       gateway_frames, "charge failed", req={"method": "POST", "url": "/v1/charges"},
                                       res={"statusCode": 504}))
        early_refunds = [node_error(minutes_ago, "TypeError", "Cannot read properties of undefined (reading 'amount')",
                                    refund_frames, "refund failed") for minutes_ago in (1200, 1150)]
        later_refunds = [node_error(minutes_ago, "TypeError", "Cannot read properties of undefined (reading 'amount')",
                                    refund_frames, "refund failed") for minutes_ago in (45, 12)]

        def released(records, deployed_minutes_ago, before, after):
            """Each record names the version that was running when it was logged."""
            cutoff = at(deployed_minutes_ago)
            for record in records:
                when = record.get("timestamp") or record["time"] / 1000
                record["release"] = after if when >= cutoff else before
            return records

        # storefront (Laravel, PHP): records as the Densight Monolog handler sends them.
        def laravel(minutes_ago, level, message, **extra):
            return {"timestamp": at(minutes_ago), "level": level,
                    "logger": "production", "service": "storefront", "host": "store-web-1", "message": message, **extra}

        php_trace = (
            "Illuminate\\Database\\QueryException: SQLSTATE[40001]: Serialization failure: 1213 Deadlock found "
            "in /var/www/html/vendor/laravel/framework/src/Illuminate/Database/Connection.php:825\nStack trace:\n"
            "#0 /var/www/html/vendor/laravel/framework/src/Illuminate/Database/Connection.php(779): "
            "Illuminate\\Database\\Connection->runQueryCallback()\n"
            "#1 /var/www/html/app/Services/StockReservation.php(48): Illuminate\\Database\\Query\\Builder->update()\n"
            "#2 /var/www/html/app/Http/Controllers/CartController.php(31): App\\Services\\StockReservation->reserve()\n"
            "#3 {main}"
        )
        storefront = []
        for minutes_ago in range(1440, 0, -rng.randint(8, 14)):
            storefront.append(laravel(minutes_ago, "INFO", "Cart updated", method="POST", path="/cart",
                                      ip=rng.choice(customers), user_id=rng.randint(100, 900)))
        for minutes_ago in (700, 420, 180, 95, 40, 22):
            storefront.append(laravel(minutes_ago, "ERROR", "Could not reserve stock", method="POST", path="/cart",
                                      ip=rng.choice(customers), exception={
                                          "type": "Illuminate\\Database\\QueryException",
                                          "value": "SQLSTATE[40001]: Serialization failure: 1213 Deadlock found",
                                          "stacktrace": php_trace}))
        storefront.append(laravel(300, "WARNING", "Slow query (2.3 s) on products", sql_ms=2300))
        released(storefront, 1440, "5.2.0", "5.2.0")

        released(shop, 600, "2.14.0", "2.15.0")
        released(payments + early_refunds + later_refunds, 1100, "3.8.1", "3.8.2")

        apps = {"shop-api": (LogSource.OS.PYTHON, shop), "payments": (LogSource.OS.NODE, payments),
                "storefront": (LogSource.OS.PHP, storefront)}
        for name, (kind, records) in apps.items():
            source = LogSource(organization=organization, name=name, os=kind, created_by=people["owner"])
            source.issue_key()
            source.save()
            if name == "payments":
                # The team's own alert, which the gateway outage sets off.
                LogAlertRule.objects.create(
                    organization=organization, name="Card gateway timing out", contains="gateway timed out",
                    source=source, threshold=20, window_minutes=5, severity="high", created_by=people["amina"],
                )
                # The refund bug, "fixed" yesterday -- and back today.
                analyze(source, store(source, early_refunds))
                ErrorGroup.objects.filter(source=source, exception_type="TypeError").update(
                    status=ErrorGroup.Status.RESOLVED, resolved_at=now - timedelta(minutes=1000))
                records = records + later_refunds
            batch = sorted(records, key=lambda r: r.get("timestamp") or r["time"] / 1000)
            for start in range(0, len(batch), 60):
                analyze(source, store(source, batch[start:start + 60]))
            LogSource.objects.filter(id=source.id).update(created_at=now - timedelta(days=2))
        LogAlertRule.objects.create(
            organization=organization, name="Disk full", contains="No space left on device", threshold=1,
            window_minutes=60, severity="critical", created_by=people["amina"],
        )

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
