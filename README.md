<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="frontend/public/brand/logo-dark.svg">
    <img src="frontend/public/brand/logo-light.svg" alt="Densight" height="72">
  </picture>
</p>

<p align="center"><b>See your attack surface the way attackers do.</b></p>

# Densight

Densight (from **Den**nis and in**sight**) is a lightweight attack surface management platform. Point it at a domain
you control and it discovers subdomains, scans them, tracks what
changes between runs, scores the risk, and emails you about new
findings.

- **Backend** — Django + DRF, Celery workers, Postgres, Redis (`backend/`)
- **Frontend** — Angular 20 single-page app (`frontend/`)

## Brand

The logo is a D whose bowl holds a radar eye: the sweep, the pupil, and one exposure found (in amber).
The files are in [`frontend/public/brand/`](frontend/public/brand/): `mark.svg` (the square mark),
`logo-light.svg` and `logo-dark.svg` (mark and name, for light and dark backgrounds) and
`og-image.png` (the picture shown when a link is shared). The browser icons (`favicon.svg`, `favicon.ico`,
`apple-touch-icon.png`, `icon-192.png`, `icon-512.png`) are in `frontend/public/`.

## Screenshots

The interface follows your system's light or dark setting, and can be
switched from the sidebar. Every screen below is shown in both. The data
is the fictional demo organization (see [Demo data](#demo-data)).

<table>
  <tr>
    <th width="50%">Light</th>
    <th width="50%">Dark</th>
  </tr>
  <tr>
    <td colspan="2"><b>Dashboard</b><br>A plain-English summary, the risk grade, the 90-day trend, remediation figures and what changed this week.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/dashboard-light.png" alt="Dashboard in light mode"></td>
    <td><img src="docs/screenshots/dashboard-dark.png" alt="Dashboard in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Attack surface map</b><br>Every host around the domain; the closer and larger, the more open issues it has.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/surface-map-light.png" alt="Attack surface map in light mode"></td>
    <td><img src="docs/screenshots/surface-map-dark.png" alt="Attack surface map in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Findings</b><br>Most severe first, with an owner, a fix-by date, related compliance controls, and why it matters and what to do.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/findings-light.png" alt="Findings in light mode"></td>
    <td><img src="docs/screenshots/findings-dark.png" alt="Findings in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Fix plan</b><br>Every open issue grouped into the action that fixes it, most urgent first, with the grade you reach after each step.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/fix-plan-light.png" alt="Fix plan in light mode"></td>
    <td><img src="docs/screenshots/fix-plan-dark.png" alt="Fix plan in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>One finding</b><br>Why it matters, what to do, the MITRE ATT&amp;CK technique it enables, and its whole history and discussion.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/finding-detail-light.png" alt="Finding detail in light mode"></td>
    <td><img src="docs/screenshots/finding-detail-dark.png" alt="Finding detail in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>My work</b><br>Your own open issues, grouped by deadline.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/my-work-light.png" alt="My work in light mode"></td>
    <td><img src="docs/screenshots/my-work-dark.png" alt="My work in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Compliance</b><br>Open issues mapped to OWASP Top 10, CIS Controls, ISO 27001 and PCI DSS.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/compliance-light.png" alt="Compliance in light mode"></td>
    <td><img src="docs/screenshots/compliance-dark.png" alt="Compliance in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Assets</b><br>Every host found under the domain, with detected technologies and a grade.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/assets-light.png" alt="Assets in light mode"></td>
    <td><img src="docs/screenshots/assets-dark.png" alt="Assets in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>One host</b><br>Its grade, open issues, ports, certificate, software, screenshot and scans, plus how much it matters to the business.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/asset-detail-light.png" alt="Host detail in light mode"></td>
    <td><img src="docs/screenshots/asset-detail-dark.png" alt="Host detail in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Inventory</b><br>Software and versions, open services, and TLS certificates by expiry date.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/inventory-light.png" alt="Inventory in light mode"></td>
    <td><img src="docs/screenshots/inventory-dark.png" alt="Inventory in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Screenshots</b><br>What each site looked like when it was last captured.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/screenshots-light.png" alt="Screenshots in light mode"></td>
    <td><img src="docs/screenshots/screenshots-dark.png" alt="Screenshots in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Scanners</b><br>Eighteen checks in five groups; one click runs a check across the whole domain.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/scanners-light.png" alt="Scanners in light mode"></td>
    <td><img src="docs/screenshots/scanners-dark.png" alt="Scanners in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Scan history</b><br>Every scan that has run, with its status.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/scan-history-light.png" alt="Scan history in light mode"></td>
    <td><img src="docs/screenshots/scan-history-dark.png" alt="Scan history in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Activity</b><br>The audit trail: who did what, and when.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/activity-light.png" alt="Activity in light mode"></td>
    <td><img src="docs/screenshots/activity-dark.png" alt="Activity in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Organization</b><br>Domain verification and the team, with a role per member.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/organization-light.png" alt="Organization in light mode"></td>
    <td><img src="docs/screenshots/organization-dark.png" alt="Organization in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Notifications</b><br>Email and chat alerts for new findings, and who gets the weekly PDF report.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/notifications-light.png" alt="Notifications in light mode"></td>
    <td><img src="docs/screenshots/notifications-dark.png" alt="Notifications in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Sign in</b></td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/login-light.png" alt="Sign in in light mode"></td>
    <td><img src="docs/screenshots/login-dark.png" alt="Sign in in dark mode"></td>
  </tr>
</table>

## What it does

| Scanner       | Targets      | Finds                                             |
|---------------|--------------|---------------------------------------------------|
| `subfinder`   | organization | Subdomains (each becomes an asset)                |
| `nmap`        | asset        | Open ports                                        |
| `httpx`       | asset        | Missing security headers, server technologies     |
| `ssl_expiry`  | asset        | Expired / expiring TLS certificates               |
| `dns_monitor` | asset        | DNS records and changes to them                   |
| `nuclei`      | asset        | Known vulnerabilities and misconfigurations       |
| `screenshot`  | asset        | Screenshots of the home page and the pages it links to |
| `email_security` | organization | Missing or weak SPF, DKIM and DMARC records (who can send email as your domain) |
| `subdomain_takeover` | asset | Subdomains still pointing at a hosting or cloud service that is no longer there |
| `tls_config`  | asset        | Retired TLS versions and certificates browsers do not trust |
| `outdated_software` | asset  | Web servers and frameworks announcing an end-of-life version |
| `security_txt` | organization | A missing, incomplete or expired `security.txt` contact file |
| `exposed_files` | asset      | A `.git` directory, `.env` file, database dump or config backup left downloadable |
| `dns_zone_transfer` | organization | Nameservers that give the complete DNS zone to anyone who asks |
| `cors`        | asset        | Sites that let any other website read logged-in users' data |
| `cookie_security` | asset    | Cookies, especially session cookies, missing Secure, HttpOnly or SameSite |
| `https_enforcement` | asset  | Sites still served over unencrypted HTTP instead of redirecting to HTTPS |
| `lookalike_domains` | organization | Registered domains imitating yours (typos, look-alike characters, other endings) that could be used for phishing; DNS lookups only |

Beyond the raw findings, the platform is built to answer the questions
people actually ask about their security:

| Question | Where it's answered |
|---|---|
| What do we have online? | **Assets** and the **Attack surface** map; hosts discovery can't see can be added by hand |
| What's wrong, and what first? | **Findings**, most severe first, each with why it matters and what to do; the **Fix plan** turns them into a to-do list ranked by urgency and business importance, with the grade each step gets you |
| Are we getting better? | The dashboard's **90-day risk trend** and plain-English **In short** summary |
| What changed this week? | **What changed**: new hosts, new issues, issues resolved |
| Who is fixing what, by when? | An **owner** and a **fix-by date** on every issue (from each organization's own SLA), **My work** for each person, **bulk** assignment and triage, a **discussion** under every finding, overdue tracking and mean time to fix |
| Which hosts matter most? | Mark hosts as **crown jewels** (or high, normal, low) and label them; their issues go first |
| Where does that vulnerable version run? Is RDP open anywhere? What certificate expires next? | **Inventory**: software and versions, open services, certificates |
| Did the fix stick? | **Re-check this host** after a fix; an issue that comes back after being fixed is flagged **Came back** |
| Is anyone impersonating us? | **Lookalike domains**: registered typo-domains that can send email or host a fake site |
| How would an attacker use this? | Every issue names the **MITRE ATT&CK** technique it opens the door to |
| Does this help with audits? | **Compliance**: issues mapped to OWASP Top 10, CIS Controls v8, ISO/IEC 27001:2022, PCI DSS v4.0 and MITRE ATT&CK (indicative, not an assessment) |
| What are we not allowed to test? | A **never-scan list**: hosts someone else runs are kept in the inventory but never scanned |
| We accepted a risk. Until when? | Risk acceptances can have an **end date**; the issue reopens by itself on that day |
| Who did what? | The **Activity** log, and each finding's own history |
| How do people who never log in stay informed? | **Alerts & reports**: an email or chat message (Slack, Teams) when a scan finds something new, set up in three plain questions with a test send; a **weekly PDF report** every Monday; **Download report**; and **Copy as ticket** for Jira or GitHub |

The grade is the average score of the hosts that have open issues, and
an open critical issue caps it at C (an open high issue at B), so a
large, tidy estate can never hide one serious exposure. The fix-by
targets default to `REMEDIATION_SLA_DAYS` (critical 7 days, high 30,
medium 90, low 180); each organization can set its own on the
Organization page.

Press **Ctrl+K** (or **⌘K**, or **/**) anywhere to jump to a page, a host or an issue.
Press **?** for keyboard shortcuts: **g** then a letter jumps to a page
(**g p** fix plan, **g f** findings, **g b** board view…).

A few more things for day-to-day use:

- **Board view** (`/board`, or *Board view* on the dashboard): the grade, the
  story, the headline numbers and the next three fixes in large type for a
  meeting-room or wall screen. Refreshes every minute; *Full screen* hides
  everything else.
- **Where the risk is**: a heatmap on the dashboard of open issues by kind and
  severity; each square opens those findings.
- **Grade, day by day**: a 90-day calendar of the daily grade under the trend.
- **What's new**: the bell next to the logo lists recent team activity, counts
  what's new since you last looked, and marks anything that names you.

Scans are started per domain, not per host: **Run scan** on the Scanners
page runs that scanner once for the organization (subdomain discovery)
or once for every asset in it (everything else), and the card shows how
far the run has got. A single asset can still be scanned through the
API (`asset_id`) or re-run from Scan history.

Scanners are plugins: drop a file in `backend/apps/scanning/plugins/`
that subclasses `BaseScanner` and it shows up in the API, the UI and the
daily run with no other changes.

Findings are never deleted. Each scan upserts them, so a finding that
stops appearing is marked resolved and one that appears is new. Analysts
can mark a finding as an accepted risk or a false positive; those stop
counting toward the asset's risk score (0–100, graded A+ to F).

## Run it locally

Requires Docker and Node 22.

```bash
cp .env.example .env
docker compose up --build

# first run only
docker compose exec api python manage.py migrate
docker compose exec api python manage.py createsuperuser
docker compose exec api python manage.py setup_periodic_tasks
```

```bash
cd frontend
npm install
npm start          # http://localhost:4200
```

Log in with the superuser. Check the stack is healthy with
`curl http://localhost:8000/health/`.

| URL                               | What                                  |
|-----------------------------------|---------------------------------------|
| http://localhost:4200             | The app                               |
| http://localhost:8000/api/docs/   | Swagger UI for the API                |
| http://localhost:8000/admin/      | Django admin (users, memberships)     |
| http://localhost:8000/metrics     | Prometheus metrics (dev only, see below) |

Notification emails are printed to the `celery-worker` logs unless SMTP
is configured in `.env`.

### First steps in the app

A user with no organization lands on the **Organization** page and is
asked for a name and a root domain. Whoever creates an organization
becomes its Owner, and the root domain is added as its first asset. The
same page shows the DNS record for domain verification and manages the
team: admins add existing accounts by username or email and set their
role. Accounts themselves are still created in the Django admin.

## Demo data

For a demonstration, load a realistic but entirely fictional
organization:

```bash
docker compose exec api python manage.py load_demo_data --owner <your username>
```

It creates **Acme Retail** on `acme-retail.example` (a reserved domain
that doesn't exist on the internet) with 46 hosts, about 25 open issues
across every scanner, issues fixed over the last few weeks, owners and
fix-by dates (some overdue, a few assigned to you), crown-jewel hosts and
labels, a never-scan list, discussions on findings, an issue that came
back after a fix, lookalike domains, certificates and open services,
three colleagues, alerts (email and Slack), website screenshots, an activity
log and 90 days of risk history. Pick it from the organization switcher.

Run it again with `--reset` to start the demo from scratch. Don't press
**Run scan** on it: the domain doesn't exist, so live scans of it just
fail. Show live scanning on a domain you own instead.

## Roles

Every role includes the ones above it.

| Role    | Can                                                             |
|---------|-----------------------------------------------------------------|
| Viewer  | Read assets, findings, scan history; export reports             |
| Analyst | Trigger scans; triage findings                                  |
| Admin   | Manage alerts and reports, and organization settings; verify the domain |
| Owner   | Delete the organization                                         |

Users only ever see organizations they are a member of. Superusers see
everything.

## Account security and integrations

- **Two-factor sign-in.** Each person can turn on authenticator-app codes
  (TOTP) under Account settings. Lost phone: an administrator deletes the
  person's row under *Two factor devices* in the Django admin.
- **Sign-in history.** Account settings lists recent sign-ins and failed
  attempts on your username.
- **API keys.** Read-only keys for scripts and integrations (a SIEM, a CI
  job), created under Account settings and shown once. A key sees what its
  owner sees and can never change anything:

  ```bash
  curl -H "Authorization: Api-Key sasm_..." \
    "http://localhost:8000/api/findings/?severity=critical&is_active=true"
  ```

  The full API is documented at `/api/docs/`.

## Scan safety

This platform runs nmap and nuclei against whatever it is pointed at, so
it limits what that can be:

- **Domain verification.** Before an organization can be scanned, an
  admin publishes a DNS TXT record (shown on the Scanners page) and
  clicks *Check record*. On by default whenever `DJANGO_DEBUG` is off;
  off in local development. Controlled by `ASM_REQUIRE_DOMAIN_VERIFICATION`.
- **Public targets only.** A root domain must be a real public DNS name,
  and a scan is refused if its target resolves to a loopback, private or
  link-local address. Override with `ASM_ALLOW_PRIVATE_SCAN_TARGETS` if
  you are deliberately scanning your own internal network.
- **Never-scan list.** Hosts under the domain that someone else runs (a
  hosted shop, a status page) can be excluded on the Organization page;
  every scanner skips them, including jobs queued before the change.
- `nuclei` runs the full community template set, including active
  checks. Only scan what you are authorized to test.

Known gaps: the public-target check runs once before the scanner starts,
so it does not stop a host that redirects to an internal address
mid-scan; and `root_domain` is unique across the whole instance, so the
first organization to claim a domain holds it even if unverified.

## Tests and linting

```bash
# backend (needs the compose stack's db and redis running)
docker compose exec api python manage.py test
cd backend && ruff check .

# frontend
cd frontend
npm run lint
npm test -- --watch=false --browsers=ChromeHeadless
npm run build
```

CI (`.github/workflows/ci.yml`) runs all of the above on every push and
pull request.

## Deploying

`docker-compose.prod.yml` is a production-shaped stack: gunicorn, the
built frontend served by nginx, and only nginx published to the host.

```bash
# in .env: set DJANGO_SECRET_KEY, DJANGO_ALLOWED_HOSTS, strong Postgres
# credentials, and SMTP settings
docker compose -f docker-compose.prod.yml up --build -d
docker compose -f docker-compose.prod.yml exec api python manage.py createsuperuser
```

Migrations, static files and the periodic tasks are set up when the
`api` container starts. Put TLS in front of nginx (a load balancer,
Caddy, Cloudflare) and set `DJANGO_HTTPS=True` and
`CSRF_TRUSTED_ORIGINS`. `.env.example` documents every setting.

`/metrics` is not exposed through nginx. To scrape it, set
`METRICS_TOKEN` and have Prometheus reach `api:8000` on the compose
network with that bearer token.

Screenshots are stored on a Docker volume shared by the worker and the
API, which ties both to one host. Move them to object storage before
running workers on more than one machine.

## How it fits together

```
Angular app ──HTTP──> Django API ──enqueue──> Redis ──> Celery worker ──> scanner plugin
                          │                                   │
                          └───────────── Postgres <───────────┘
                                             ▲
                     celery-beat: daily scans, stale-job cleanup
```

- `apps/organizations` — tenants, memberships and roles, domain verification
- `apps/assets` — hosts and detected technologies
- `apps/scanning` — scan jobs, the plugin registry, the Celery tasks
- `apps/findings` — findings, risk scoring, CSV/JSON/PDF export
- `apps/notifications` — email rules and digests
- `apps/audit_logs` — login, logout and password-change history
- `apps/api` — the REST viewsets and permission checks

Two images are built from `backend/`: `Dockerfile.api` (Django only) and
`Dockerfile.worker` (adds nmap, subfinder, nuclei and Chromium). A scan
that outlives its time limit, or whose worker dies, is marked failed by
a periodic task so it can be re-run.
