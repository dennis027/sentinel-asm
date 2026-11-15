<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="frontend/public/brand/logo-dark.svg">
    <img src="frontend/public/brand/logo-light.svg" alt="Densight" height="72">
  </picture>
</p>

<p align="center"><b>See your attack surface the way attackers do.</b></p>

<p align="center">
  <a href="https://github.com/dennis027/sentinel-asm/actions/workflows/deploy.yml"><img src="https://github.com/dennis027/sentinel-asm/actions/workflows/deploy.yml/badge.svg" alt="Deploy"></a>
  <img src="https://img.shields.io/badge/Django-6.0-0c4b33" alt="Django 6.0">
  <img src="https://img.shields.io/badge/Angular-20-dd0031" alt="Angular 20">
  <img src="https://img.shields.io/badge/Python-3.12-3776ab" alt="Python 3.12">
  <img src="https://img.shields.io/badge/scanners-25-4f46e5" alt="25 scanners">
</p>

# Densight

Densight (from **Den**nis and in**sight**) is a self-hosted attack surface management platform. Point it at
a domain you control and it finds every host under it, checks each one for the weaknesses attackers look for
first, tracks what changes from day to day, grades the risk, and tells the right person what to fix, by
when, in plain language.

It also watches what happens **on** your servers and **in** your applications: sign-ins, admin changes,
errors with their stack traces, and the signs of an attack or an outage.

| | |
|---|---|
| **Backend** | Django 6 + Django REST Framework, Celery workers, Postgres, Redis (`backend/`) |
| **Frontend** | Angular 20 single-page app, light and dark (`frontend/`) |
| **Scanners** | 25 plugins: subfinder, nmap, nuclei, a headless browser, and 21 written for this project |
| **Runs on** | Docker Compose (development and production), or Render + Neon + GitHub Pages |

## Contents

- [What you get](#what-you-get)
- [Screenshots](#screenshots)
- [Quick start](#quick-start)
- [Demo data](#demo-data)
- [The scanners](#the-scanners)
- [Scanning: the check before, and what happens during](#scanning-the-check-before-and-what-happens-during)
- [Knowing your attack surface](#knowing-your-attack-surface)
- [Fixing things as a team](#fixing-things-as-a-team)
- [Logs: servers and applications](#logs-servers-and-applications)
- [User accounts and roles](#user-accounts-and-roles)
- [Security of the platform itself](#security-of-the-platform-itself)
- [The API](#the-api)
- [Configuration](#configuration)
- [Tests and linting](#tests-and-linting)
- [Deploying](#deploying)
- [How it fits together](#how-it-fits-together)
- [Troubleshooting](#troubleshooting)
- [Known limits](#known-limits)
- [Brand](#brand)

## What you get

The platform is built around the questions people actually ask about their security.

| Question | Where it's answered |
|---|---|
| What do we have online? | **Assets** and the **Attack surface map**; hosts discovery can't see can be added by hand or imported as a list |
| How does each host answer, and who hosts it? | The last **web response** (status, page title, where it redirects, how fast) and the **hosting provider** on every host; **Inventory → Hosting** groups hosts by provider |
| What's wrong, and what first? | **Findings**, most severe first, each with why it matters and what to do; the **Fix plan** turns them into a to-do list ranked by urgency and business importance, with the grade each step gets you |
| Is anyone actually exploiting what we have? | Issues whose CVE is in **CISA's Known Exploited Vulnerabilities** list are badged **Exploited in the wild** and lead the fix plan; the dashboard lists recently exploited vulnerabilities in **software you run** |
| What changed? | **Changes**: new and vanished hosts, ports opened and closed, new software, certificates and DNS records, day by day |
| Are we getting better? | The dashboard's **90-day risk trend**, daily grade calendar and plain-English **In short** summary |
| Who is fixing what, by when? | A **host owner** who gets new issues automatically, an **owner** and a **fix-by date** on every issue (from each organization's own SLA), **My work**, **bulk** assignment and triage, a **discussion** under every finding, overdue tracking and mean time to fix |
| What must never be exposed? | **Policies**: your own rules ("no Remote Desktop on the internet"); a host that breaks one gets a finding |
| Which hosts matter most? | Mark hosts as **crown jewels** (or high, normal, low) and label them; their issues go first |
| Where does that vulnerable version run? Is RDP open anywhere? What certificate expires next? | **Inventory**: software and versions, open services, certificates; or the Assets search: `tech:apache`, `port:3389` |
| Will this scan work? How long will it take? | **The check before a scan**: hosts in scope, which still exist in DNS, scanners that can't run, and an estimate |
| Did the fix stick? | **Re-check this host** after a fix; an issue that comes back after being fixed is flagged **Came back** |
| Is anyone impersonating us? | **Lookalike domains**: registered typo-domains that can send email or host a fake site |
| How would an attacker use this? | Every issue names the **MITRE ATT&CK** technique it opens the door to |
| Does this help with audits? | **Compliance**: issues mapped to OWASP Top 10, CIS Controls v8, ISO/IEC 27001:2022, PCI DSS v4.0 and MITRE ATT&CK (indicative, not an assessment) |
| What are we not allowed to test? | A **never-scan list**: hosts someone else runs are kept in the inventory but never scanned |
| We accepted a risk. Until when? | Risk acceptances can have an **end date**; the issue reopens by itself on that day |
| Why is our app failing, and is someone attacking it? | **Logs**: each distinct application error once, with its count and stack trace; error spikes, attack probes and password guessing are flagged |
| Who did what? | The **Activity** log, and each finding's own history |
| How do people who never log in stay informed? | **Alerts & reports**: an email or chat message (Slack, Teams) when a scan finds something new; a **weekly PDF report**; **Download report**; **Copy as ticket** for Jira or GitHub |

## Screenshots

The interface follows your system's light or dark setting, and can be switched from the sidebar. Every
screen is shown in both. The data is the fictional demo organization (see [Demo data](#demo-data)).

<table>
  <tr>
    <th width="50%">Light</th>
    <th width="50%">Dark</th>
  </tr>
  <tr>
    <td colspan="2"><b>Dashboard</b><br>The setup checklist, a plain-English summary, the risk grade, the 90-day trend, remediation figures, what changed this week and vulnerabilities being exploited in software you run.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/dashboard-light.png" alt="Dashboard in light mode"></td>
    <td><img src="docs/screenshots/dashboard-dark.png" alt="Dashboard in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Attack surface map</b><br>Every host around the domain; the closer and larger, the more open issues it has. Legend items hide and show grades; clicking a host opens its summary.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/surface-map-light.png" alt="Attack surface map in light mode"></td>
    <td><img src="docs/screenshots/surface-map-dark.png" alt="Attack surface map in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Attack surface map, by hosting</b><br>The same hosts arranged by who hosts them: one slice per provider.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/surface-map-hosting-light.png" alt="Attack surface map arranged by hosting in light mode"></td>
    <td><img src="docs/screenshots/surface-map-hosting-dark.png" alt="Attack surface map arranged by hosting in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Assets</b><br>Every host with its last web response, hosting provider, owner, importance and grade, searched with terms like <code>tech:nginx provider:aws owner:me</code>.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/assets-light.png" alt="Assets in light mode"></td>
    <td><img src="docs/screenshots/assets-dark.png" alt="Assets in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Host quick view</b><br>Click a row (or a host on the map) for the essentials without leaving the page; set the owner here.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/asset-peek-light.png" alt="Host quick view in light mode"></td>
    <td><img src="docs/screenshots/asset-peek-dark.png" alt="Host quick view in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Findings</b><br>Most severe first, with an owner, a fix-by date, related compliance controls, why it matters and what to do. Filters can be saved as views.</td>
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
    <td colspan="2"><b>The check before a scan</b><br>What a scan will cover and what would stop it: hosts in scope, which still exist in DNS, scanners that can't run, and how long it will take.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/preflight-light.png" alt="The check before a scan in light mode"></td>
    <td><img src="docs/screenshots/preflight-dark.png" alt="The check before a scan in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Changes</b><br>What appeared and disappeared: hosts, ports, software, certificates and DNS records, day by day.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/changes-light.png" alt="Changes in light mode"></td>
    <td><img src="docs/screenshots/changes-dark.png" alt="Changes in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Policies</b><br>Your own rules for what may be exposed. A host that breaks one gets a finding.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/policies-light.png" alt="Policies in light mode"></td>
    <td><img src="docs/screenshots/policies-dark.png" alt="Policies in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Logs</b><br>Sign-ins and admin activity on your servers, and errors and requests from your applications, watched for attacks and outages.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/logs-light.png" alt="Logs in light mode"></td>
    <td><img src="docs/screenshots/logs-dark.png" alt="Logs in dark mode"></td>
  </tr>
</table>

### More screens

<table>
  <tr>
    <th width="50%">Light</th>
    <th width="50%">Dark</th>
  </tr>
  <tr>
    <td colspan="2"><b>One finding</b><br>Why it matters, what to do, the MITRE ATT&amp;CK technique it enables, and its whole history and discussion.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/finding-detail-light.png" alt="Finding detail in light mode"></td>
    <td><img src="docs/screenshots/finding-detail-dark.png" alt="Finding detail in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>One host</b><br>Its grade, open issues, ports, web response, hosting, certificate, software, screenshot and scans, plus its owner and how much it matters to the business.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/asset-detail-light.png" alt="Host detail in light mode"></td>
    <td><img src="docs/screenshots/asset-detail-dark.png" alt="Host detail in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>My work</b><br>Your own open issues, grouped by deadline.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/my-work-light.png" alt="My work in light mode"></td>
    <td><img src="docs/screenshots/my-work-dark.png" alt="My work in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Inventory</b><br>Software and versions, open services, and TLS certificates by expiry date.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/inventory-light.png" alt="Inventory in light mode"></td>
    <td><img src="docs/screenshots/inventory-dark.png" alt="Inventory in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Inventory: hosting</b><br>Hosts grouped by provider, and addresses that several names share.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/inventory-hosting-light.png" alt="Inventory hosting tab in light mode"></td>
    <td><img src="docs/screenshots/inventory-hosting-dark.png" alt="Inventory hosting tab in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Compliance</b><br>Open issues mapped to OWASP Top 10, CIS Controls, ISO 27001, PCI DSS and MITRE ATT&amp;CK.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/compliance-light.png" alt="Compliance in light mode"></td>
    <td><img src="docs/screenshots/compliance-dark.png" alt="Compliance in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Screenshots</b><br>What each site looked like when it was last captured.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/screenshots-light.png" alt="Screenshots in light mode"></td>
    <td><img src="docs/screenshots/screenshots-dark.png" alt="Screenshots in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Scanners</b><br>Twenty-five checks in five groups; one click runs a check across the whole domain.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/scanners-light.png" alt="Scanners in light mode"></td>
    <td><img src="docs/screenshots/scanners-dark.png" alt="Scanners in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Scan history</b><br>Every scan grouped by where it came from: the daily schedule, a Run scan click, a re-check of one host.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/scan-history-light.png" alt="Scan history in light mode"></td>
    <td><img src="docs/screenshots/scan-history-dark.png" alt="Scan history in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Board view</b><br>The grade, the story and the next three fixes in large type, for a meeting room or a wall screen.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/board-light.png" alt="Board view in light mode"></td>
    <td><img src="docs/screenshots/board-dark.png" alt="Board view in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Search</b><br><b>Ctrl+K</b> jumps to any page, host or issue.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/command-palette-light.png" alt="Command palette in light mode"></td>
    <td><img src="docs/screenshots/command-palette-dark.png" alt="Command palette in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Activity</b><br>The audit trail: who did what, and when.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/activity-light.png" alt="Activity in light mode"></td>
    <td><img src="docs/screenshots/activity-dark.png" alt="Activity in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Organization</b><br>Domain verification, fix-by deadlines, the never-scan list and the team, with invitations and a role per member.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/organization-light.png" alt="Organization in light mode"></td>
    <td><img src="docs/screenshots/organization-dark.png" alt="Organization in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Alerts &amp; reports</b><br>Email and chat alerts for new findings, and who gets the weekly PDF report.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/notifications-light.png" alt="Alerts and reports in light mode"></td>
    <td><img src="docs/screenshots/notifications-dark.png" alt="Alerts and reports in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Account settings</b><br>Profile, email, password, two-factor sign-in, API keys and recent sign-ins.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/account-settings-light.png" alt="Account settings in light mode"></td>
    <td><img src="docs/screenshots/account-settings-dark.png" alt="Account settings in dark mode"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Sign in</b><br>With a username or an email address.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/login-light.png" alt="Sign in in light mode"></td>
    <td><img src="docs/screenshots/login-dark.png" alt="Sign in in dark mode"></td>
  </tr>
</table>


## Quick start

You need Docker (with Compose) and Node 22.

```bash
git clone https://github.com/dennis027/sentinel-asm.git
cd sentinel-asm

# 1. The API, the scan worker, the scheduler, Postgres and Redis
cp .env.example .env
docker compose up --build -d

# 2. First run only: the database, your account, the daily schedule
docker compose exec api python manage.py migrate
docker compose exec api python manage.py createsuperuser
docker compose exec api python manage.py setup_periodic_tasks

# 3. The web app
cd frontend
npm install
npm start          # http://localhost:4200
```

Sign in with the account you just created. `curl http://localhost:8000/health/` says whether the API can
reach its database and Redis.

| URL | What |
|---|---|
| http://localhost:4200 | The app |
| http://localhost:8000/api/docs/ | Swagger UI for the API (`/api/redoc/` for ReDoc) |
| http://localhost:8000/admin/ | Django admin |
| http://localhost:8000/metrics | Prometheus metrics (development only; see [Configuration](#configuration)) |

Emails (alerts, invitations, password resets) are printed to the `celery-worker` and `api` logs unless
SMTP is set in `.env`.

### First steps in the app

1. A new account lands on **Organization**: give it a name and the root domain you control. You become its
   Owner and the domain becomes its first asset.
2. The dashboard's **Get the most out of Densight** checklist walks through the rest: verify the domain,
   find your hosts, run a full scan, mark what matters most, give hosts an owner, invite your team, turn on
   alerts, protect your account.
3. **Scanners → Subdomain discovery** fills in the inventory; **Run all scanners** (or *Run a scan* on the
   dashboard) checks every host. After that everything runs by itself once a day, at 02:00 UTC.

Locally, domain verification is off (`DJANGO_DEBUG=True`), so you can scan straight away. Only scan what
you are authorized to test.

## Demo data

For a demonstration, load a realistic but entirely fictional organization:

```bash
docker compose exec api python manage.py load_demo_data --owner <your username>
```

It creates **Acme Retail** on `acme-retail.example` (a reserved domain that doesn't exist on the internet)
with 46 hosts and three months of history:

- about 55 open issues from every scanner, issues fixed over the last few weeks, one that came back after a
  fix, and one on CISA's exploited list;
- each host's web response and hosting provider (AWS, Cloudflare, Hetzner, Vercel…), host owners, crown
  jewels and labels, a never-scan list;
- three policies with a host breaking each, shared saved views, a change feed;
- three colleagues, discussions on findings, fix-by dates (some overdue, a few assigned to you);
- server and application logs with detections, grouped errors and releases;
- alerts (email and Slack), website screenshots, scan history, an activity log and 90 days of risk history.

Pick it from the organization switcher. Run the command again with `--reset` to start from scratch.
[`docs/DEMO.md`](docs/DEMO.md) is a 12-minute walkthrough with what to click and what to say.

Don't run scans on the demo organization. Its domain doesn't exist, so scanners that connect to hosts skip
every one of them, and scanners that only read DNS see nothing there and mark the demo's findings as
resolved. Show live scanning on a domain you own.

## The scanners

Twenty-five checks in five groups. Each runs once for the organization or once per host.

| Group | Scanner | Runs on | Finds |
|---|---|---|---|
| **Discovery & inventory** | `subfinder` Subdomain discovery | organization | Subdomains, from public sources; each becomes an asset |
| | `cert_transparency` Certificate transparency | organization | Every certificate issued for the domain, from the public CT logs: hostnames nobody listed, and certificates from an issuer you don't normally use |
| | `cloud_storage` Public cloud storage | organization | Amazon S3 and Google Cloud Storage buckets named after the company whose contents anyone can list; reads the listing only |
| | `dns_monitor` DNS records | host | DNS records and changes to them; also the host's addresses and who hosts it |
| | `screenshot` Screenshot | host | Pictures of the home page and the pages it links to |
| **Web applications** | `httpx` Security headers | host | Missing security headers; also the response status, page title, response time and server software |
| | `nuclei` Vulnerability scan | host | Known vulnerabilities and misconfigurations (the community template set) |
| | `outdated_software` Outdated software | host | Web servers and frameworks announcing an end-of-life version |
| | `exposed_files` Exposed sensitive files | host | A `.git` directory, `.env` file, database dump or config backup left downloadable |
| | `admin_panels` Exposed admin panels | host | Login pages that should not face the internet: phpMyAdmin, Jenkins, Grafana, Kibana, router and hosting panels |
| | `api_exposure` API documentation & GraphQL | host | Public OpenAPI/Swagger documents and consoles, and GraphQL servers that describe their whole schema |
| | `js_secrets` Secrets in JavaScript | host | API keys, tokens and private keys in the JavaScript a site sends to every visitor (Stripe, AWS, GitHub, Slack…); shown masked, never stored in full |
| | `cors` CORS misconfiguration | host | Sites that let any other website read logged-in users' data |
| | `cookie_security` Cookie security | host | Cookies, especially session cookies, missing Secure, HttpOnly or SameSite |
| **Encryption** | `ssl_expiry` TLS certificate | host | Expired and expiring certificates |
| | `tls_config` TLS configuration | host | Retired TLS versions and certificates browsers do not trust |
| | `https_enforcement` HTTPS enforcement | host | Sites still served over plain HTTP instead of redirecting |
| **Network** | `nmap` Port scan | host | Open ports and the services behind them |
| | `dns_zone_transfer` DNS zone transfer | organization | Nameservers that give the complete DNS zone to anyone who asks |
| **Email & domain** | `email_security` Email spoofing protection | organization | Missing or weak SPF, DKIM and DMARC records |
| | `lookalike_domains` Lookalike domains | organization | Registered domains imitating yours (typos, look-alike characters, other endings); DNS lookups only |
| | `subdomain_takeover` Subdomain takeover | host | Subdomains still pointing at a hosting or cloud service that is no longer there |
| | `dns_hygiene` DNS hygiene | organization | No CAA record, no DNSSEC, wildcard DNS, a single nameserver |
| | `domain_expiry` Domain registration | organization | The registration expiring (45, 30 and 7 days ahead) or not locked against transfer, from the registry's RDAP service |
| | `security_txt` Security contact | organization | A missing, incomplete or expired `security.txt` |

**Findings are never deleted.** Each scan upserts them, so a finding that stops appearing is marked
resolved and one that appears is new; that is what makes "what changed" and "came back after a fix"
possible. Analysts can mark a finding as an accepted risk or a false positive; those stop counting toward
the grade.

**Exploited in the wild.** Every finding that names a CVE is checked against CISA's Known Exploited
Vulnerabilities catalogue (synced daily; `python manage.py sync_kev` by hand, `--file` for an offline
copy). A match can be filtered on and goes to the top of the fix plan whatever its severity: a high that
attackers are using today beats a critical that nobody is.

**The grade.** Each host scores 0–100 (A+ to F) from its open issues. The organization's grade is the
average of the hosts that have open issues, and an open critical issue caps it at C (an open high at B),
so a large, tidy estate can never hide one serious exposure.

### Writing a scanner

Scanners are plugins. Drop a file in `backend/apps/scanning/plugins/` and it appears in the API, on the
Scanners page, in the check before a scan and in the daily run, with no other changes:

```python
from apps.findings.models import Finding
from .base import BaseScanner, RawFinding
from .registry import register_scanner


@register_scanner
class RobotsScanner(BaseScanner):
    name = "robots"
    label = "Robots file"
    description = "Looks for paths a site asks search engines not to index."
    category = "web"                      # discovery, web, encryption, network or email_domain
    applies_to = "asset"                  # or "organization"
    owned_finding_types = [Finding.FindingType.EXPOSED_FILE]
    requires_tools = []                   # programs the worker needs, e.g. ["nmap"]
    needs_address = True                  # False for DNS-only checks, where "doesn't resolve" is the answer

    def run(self, target) -> list[RawFinding]:
        ...  # return [] for "nothing found"; raise only when the scan itself failed
```

A scanner never touches the database: it returns `RawFinding`s and the task layer stores them, resolves the
ones that stopped appearing (only of the types the scanner owns), assigns new issues to the host's owner
and checks the host against the organization's policies. Optional hooks: `extract_technologies()` for
detected software and `extract_asset_facts()` for facts about the host itself (web response, hosting).

## Scanning: the check before, and what happens during

Scans are started per domain, not per host: **Run scan** on a scanner's card runs it once for the
organization (the discovery scanners) or once for every host (everything else), and the card shows how far
the run has got. One host can be scanned again with **Re-check this host**, through the API, or from Scan
history.

**Before anything starts**, a check answers what the scan will cover and what would stop it:

- how many hosts are **in scope**, and how many the never-scan list removes;
- which host names **still exist in DNS** (up to 200, the most important first, resolved in parallel), and
  which point inside a private network and are refused;
- whether each scanner **can run**: the scan worker reports every ten minutes which programs it has, so a
  missing `nmap` or `nuclei` shows before the scan instead of as hundreds of failures after it, and so does
  a worker that isn't running at all;
- whether a scanner is **already running**, how many scans this will be, and **about how long** they take,
  from how long each scanner has taken here before.

**During the run**, a host that no longer exists in DNS is **skipped**, not failed: no retries, no red, and
its findings are left alone. Scanners that only read DNS (DNS records, subdomain takeover) still run on
such a host, because "the name is gone" is their answer.

**Afterwards**, **Scan history** groups scans by where they came from: one night's schedule, one Run scan
click, one re-check. Opening a run shows **why scans didn't finish**, grouped: "38× the host doesn't
resolve in DNS" rather than 38 separate errors. A scan that outlives its time limit, or whose worker dies,
is marked failed by a periodic task so it can be run again.

### Scan safety

The platform runs nmap and nuclei against whatever it is pointed at, so it limits what that can be:

- **Domain verification.** Before an organization can be scanned, an admin publishes a DNS TXT record
  (shown on the Organization and Scanners pages) and clicks *Check record*. On whenever `DJANGO_DEBUG` is
  off. Controlled by `ASM_REQUIRE_DOMAIN_VERIFICATION`.
- **Public targets only.** A root domain must be a real public DNS name, and a scan is refused if its
  target resolves to a loopback, private or link-local address. Override with
  `ASM_ALLOW_PRIVATE_SCAN_TARGETS` if you are deliberately scanning your own internal network.
- **Assets stay inside the domain.** A host added by hand must be the organization's domain or a name
  under it.
- **Never-scan list.** Hosts someone else runs (a hosted shop, a status page) can be excluded on the
  Organization page; every scanner skips them, including scans queued before the change.
- `nuclei` runs the full community template set, including active checks. Only scan what you are
  authorized to test.

## Knowing your attack surface

**Assets.** One row per host: its page title, last web response (`200`, `301 →`, `403`, *No reply*),
hosting provider, owner, importance and grade. Click a row for the quick view; click the name for the full
page.

The search box understands terms, combined with spaces:

| Term | Matches hosts that… |
|---|---|
| `shop` | have "shop" in their name |
| `tech:nginx` | run software whose name contains "nginx" |
| `provider:aws` | are hosted there (`provider:none`: not identified) |
| `owner:amina` | are owned by her (`owner:me`, `owner:none`) |
| `status:5xx` | last answered with that status (`200`, `2xx`…`5xx`, `none`) |
| `port:22` | have that port open |
| `severity:high+` | have an open issue that severe or worse (`severity:critical` for exactly that) |
| `tag:payments` | carry the label |
| `importance:crown-jewel` | matter that much (`high`, `normal`, `low`) |
| `new:7` | were first seen in the last 7 days |
| `-tag:legacy` | a minus excludes whatever follows |

The **?** in the box lists these; the search is kept in the page address, so it can be bookmarked or sent
to a colleague.

**Saved views.** On Assets and Findings, **Views → Save current filters** keeps a set of filters under a
name, for you alone or shared with the team.

**Hosting.** Worked out from what scans already see: the names a host points at (CNAME), its addresses
(Cloudflare, Fastly and others publish theirs), reverse DNS and the Server header. *Inventory → Hosting*
shows how much of you is on each provider, what is on servers nobody could identify, and addresses that
several host names share (one server to patch, or to lose).

**Changes.** New hosts, hosts that stopped resolving, ports opened and closed, new software, new
certificates and DNS records that changed, over 7, 30 or 90 days. Built from what scans already keep, so it
needs no setup. Changes that widen what an attacker can reach are amber.

**The map.** The domain in the middle, hosts with open issues closest, sized by how many and coloured by
grade. Legend items switch grades off and on; **By hosting** gives each provider its own slice.

**Policies.** A policy says what must not be on the internet:

| Kind | Example |
|---|---|
| A port must not be open | `3389` (Remote Desktop), `5432` (Postgres), `23` (Telnet) |
| Software must not be used | `WordPress` |
| Host names must not match | `*dev*`, `staging.*` |
| Nothing may be hosted on | `Heroku` |

Each has a severity and, optionally, what to do about it. Every host is checked when a policy is added or
changed and after each scan of that host. A host that breaks one gets a **Breaks a policy** finding, which
is resolved by itself once the host complies or the policy is turned off. Admins manage them under
*Governance → Policies*.

## Fixing things as a team

- **Host owners.** Give a host an owner (in the quick view or on its page) and new issues found on it are
  assigned to that person straight away.
- **Fix-by dates.** Every issue gets one from its severity: critical 7 days, high 30, medium 90, low 180 by
  default (`REMEDIATION_SLA_DAYS`); each organization sets its own on the Organization page. Overdue issues
  are flagged everywhere.
- **Fix plan.** Open issues grouped into the action that fixes them, with the grade each step gets you;
  **Assign all to…** hands a whole fix to one person.
- **My work.** Each person's own issues by deadline, with a count in the sidebar.
- **Triage.** Accept a risk (optionally until a date) or mark a false positive, one at a time or in bulk,
  with a note. A discussion and a full history sit under every finding.
- **Alerts & reports.** An email or a chat message when a scan finds something new, set up in three plain
  questions with a test send and an estimate of how often it would have fired last month; a weekly PDF for
  people who never log in.
- **Board view** (`/board`): the grade, the story and the next three fixes in large type for a wall
  screen; refreshes every minute.
- **Getting around.** **Ctrl+K** (or **⌘K**, or **/**) jumps to a page, a host or an issue. **?** lists
  the keyboard shortcuts (**g** then a letter jumps to a page). The bell next to the logo lists recent
  team activity and marks anything that names you. The sidebar collapses to icons.

## Logs: servers and applications

Besides what the organization exposes, Densight can watch what happens **on** its servers and **in** its
applications. *Logs → Connect a server or app* gives copy-paste setup steps with the source's own key
filled in, and turns green when the first logs arrive.

### Servers

Each server (Ubuntu or other Linux, and Windows) sends its logs with [Fluent Bit](https://fluentbit.io), a
free and widely used log shipper.

- **Linux:** the system journal (SSH, sudo, `useradd`/`usermod`, PAM...).
- **Windows:** the Security and System event logs (sign-ins, account and group changes, cleared logs,
  new services).

Every event is sorted into sign-ins, failed sign-ins, admin rights, account changes, cleared logs and
services, with the user and source address pulled out, so one search works across both systems.

### Applications (Python, Node.js, PHP, Ruby, Go, Java, .NET, anything that posts JSON)

Each app sends its own log records, so errors arrive with their stack traces. Two small client files, no
dependencies, are served by Densight itself:

```python
# Python 3.8+: curl -fsSLo densight_logging.py https://densight.example.com/api/logs/clients/densight_logging.py
import logging, os
from densight_logging import DensightHandler

logging.getLogger().addHandler(DensightHandler(
    url="https://densight.example.com/api/ingest/", key=os.environ["DENSIGHT_KEY"], service="shop-api"))
```

For Django, put the same handler in `LOGGING` (`"class": "densight_logging.DensightHandler"`). It sends in
batches from a background thread, so logging never slows a request, and a Densight outage never breaks the
app. Python's own `logging.handlers.HTTPHandler` also works (key as the password of Basic auth).

```js
// Node 18+: curl -fsSLo densight-logger.js https://densight.example.com/api/logs/clients/densight-logger.js
const pino = require('pino');
const { createDensight } = require('./densight-logger');

const densight = createDensight({ url: 'https://densight.example.com/api/ingest/', key: process.env.DENSIGHT_KEY, service: 'payments' });
const logger = pino({}, pino.multistream([{ stream: process.stdout }, { stream: densight.stream }]));
// winston: transports: [new (densight.WinstonTransport())()]
```

Densight reads pino, winston, bunyan, structlog and plain `logging` records: the level (pino's numbers
too), the message, the exception and stack trace, and request fields (`method`, `path`, `status`, `ip`,
`user_agent`, or pino-http's `req`/`res`). With that it:

- **groups errors** like Sentry does: same exception type in the same function of your own code (library
  frames skipped) is one error, with a count, first and last seen, and its stack trace. Resolve one and it
  reopens, with an alert, if it happens again;
- treats a 401/403 on a login path as a **failed sign-in**, so password guessing against the app is caught
  by the same rules as SSH and RDP;
- flags **attack probes**: SQL injection, path traversal, XSS, Log4Shell strings, `/.env` and `/.git`
  requests, and scanners such as sqlmap or nuclei;
- **masks secrets before storing anything**: passwords, API keys and tokens, `Authorization` headers,
  AWS/GitHub/Slack/Stripe keys, JWTs, private keys and card numbers (Luhn-checked). The event records what
  was masked, and a detection tells the team to fix the code that logged it.

### Releases

Send the version or commit running (`release="2.15.0"` on the Python handler, `release` in
`createDensight`, or the `DENSIGHT_RELEASE` environment variable for both; any `release`/`version` field
otherwise). Each error then records the release it first appeared in and the latest one it happened in, the
Errors tab lists recent releases with the errors each introduced, and "new error" and "came back" alerts name
the release: *"Came back in release 3.8.2; it first appeared in 3.8.1."*

### Your own alerts

*Logs → What we watch for → New alert*: some text to look for (any case), optionally narrowed to one server
or app, a kind of event and a level, and how many times within how many minutes, for example "`payment
declined` 20 times within 5 minutes on payments". **Test on the last 24 hours** shows how often it would have
matched, with examples, before you turn it on. It fires as a detection like the built-in ones and goes to
your alerts by its severity. Analysts and above manage them; up to 50 per organization.

### More languages

*Logs → Connect a server or app* has copy-paste steps for each, with the app's key filled in.

| Language | How it sends | What it understands |
|---|---|---|
| Python | `densight_logging.py` (stdlib `logging` handler, Django `LOGGING`) | exceptions and stack traces, `extra` fields; survives fork (Celery, gunicorn) |
| Node.js | `densight-logger.js` (pino stream, winston transport) | `err` with stack, pino-http `req`/`res` |
| PHP | `DensightHandler.php`, a Monolog 2/3 handler (Laravel, Symfony) | exceptions with their trace, the request's method, path, address and user agent |
| Ruby | `densight_logger.rb`, a `::Logger` (Rails, Sinatra, Sidekiq) + Rails error subscriber | exceptions with backtrace, keyword fields, tagged logging; survives fork (Puma, Unicorn) |
| Go | `densight.go`, a `log/slog` handler + HTTP middleware | error types, call stacks at error level, every request, recovered panics |
| Java / Kotlin | Logback JSON (logstash-logback-encoder) or Log4j2 JSON/ECS, tailed by Fluent Bit | `stack_trace`, `level_value`, `logger_name` |
| .NET | Serilog compact JSON (`CompactJsonFormatter`), tailed by Fluent Bit | `@t`/`@l`/`@mt`/`@x`, request logging (`RequestPath`, `StatusCode`) |

Errors are grouped by the exception type and the function in your own code where it happened: library frames
(`site-packages`, `node_modules`, `vendor/`, `java.*`/`org.springframework.*`, `System.*`/`Microsoft.*`, gems,
the Go standard library) are skipped, so an error thrown inside a framework is still filed under the line of
your code that called it. Also understood when sent by other means: zap and logrus JSON, Monolog's own
`JsonFormatter`, .NET's JSON console logger, Serilog's HTTP sink, bunyan, structlog, GELF and ECS.

### Search, filters and live updates

The **Search events** tab filters by source, kind of event, level (or "warnings and errors"), HTTP status,
service, release, host, user, address and time (preset ranges or a custom one), with a count beside every
option. Typing `level:error service:payments status:5xx release:3.8.2 gateway` in the search box sets those
filters and searches the rest of the text. Each filter is in the page address, so a view can be bookmarked or
sent to a colleague; active filters show as chips that remove with one click. Above the results, a timeline
shows matching events over time (errors red, warnings amber); click a bar to zoom into it. **Export CSV**
downloads the matching events (up to 50,000).

Nothing on the Logs page needs reloading: new events appear at the top of the search within about three
seconds (highlighted as they arrive; **Live** pauses it), and the counts, detections, errors and sources
refresh every 15 seconds. It only asks for what is new since the last update, and stops while the browser tab
is hidden.

### Any other shipper

Post JSON to `POST /api/ingest/` with `Authorization: Bearer dsl_...` (or `X-Densight-Key`): an array of
records, one record, or one per line (gzip allowed). A record looks like
`{"timestamp": "...", "host": "web-01", "service": "myapp", "message": "...", "level": "error"}`; add
`error: {type, message, stack}` for exceptions and `method`, `path`, `status`, `ip` for requests.

### Detections

New ones go to your alerts by severity.

| Detection | Severity |
|---|---|
| Sign-in that worked after 5+ failures from the same address | critical |
| Security log cleared, or log files deleted | critical |
| 10+ failed sign-ins (SSH, RDP, Windows, app login) from one address in 10 minutes | high |
| One address failing against 5+ different accounts | high |
| Direct SSH sign-in as root | high |
| Account added to sudo, wheel or Administrators | high |
| A secret, password or key written to an app's logs | high |
| 25+ server errors (5xx) from an app in 5 minutes | high |
| 50+ app errors in 5 minutes | high |
| A new kind of app error; a resolved error that came back; 5+ attack probes from one address | medium |
| New account; blocked sudo attempt; new service or scheduled task; account lockout | medium |
| A server or app stops sending logs (60 minutes by default) | medium |
| Your own alerts | the severity you choose |

Logs are kept 30 days by default (7 to 365, set per organization on the Sources tab) and deleted nightly;
detections and error groups are kept. Set `ASM_LOG_INGEST_URL` to the address servers and apps can reach.
Events are stored in Postgres, which suits tens of servers and apps; for much larger volumes a dedicated
log store would be the next step.

## User accounts and roles

### Joining

People join through **invitations**: an admin enters an email address and a role under
*Organization → Members*, and the person gets a link (also shown to the admin, once, to copy, so it works
before email is set up). The link expires after 7 days, works once, and can be resent (a new link; the old
one stops working) or cancelled.

- **No account yet:** they create one from the link. Their email address is their username, and the link
  proves they received it.
- **Already have an account:** they sign in first and accept. Joining always needs the invited person: a
  link opened while signed in as someone else is refused.
- Admins invite up to Admin; only an Owner can invite an Owner. An organization always keeps at least one
  Owner. Removing a member clears the hosts they owned.

The first account is created with `createsuperuser` (or `ensure_admin`, from environment variables, where
there is no shell). Someone with an account but no organization can create their own.

### Signing in

With a username or an email address (unless two accounts share the address). **Forgot your password?**
emails a link that expires in an hour and works once; the page answers the same whether or not the address
has an account. A reset, like a password change, signs out every device and emails a notice.

*Account settings* has the profile, changing the email address (needs the current password; the old
address is told), **two-factor sign-in** with an authenticator app, **read-only API keys**, the **sign-in
history** including failed attempts, and **sign out on every device**. Lost phone: an administrator deletes
the person's row under *Two factor devices* in the Django admin.

### Roles

Every role includes the ones above it.

| Role | Can |
|---|---|
| Viewer | Read everything in the organization; export reports; save their own views; create read-only API keys |
| Analyst | Start scans; triage and assign findings; add hosts; set a host's importance, labels and owner; manage log alerts |
| Admin | Invite and remove members; alerts and reports; policies; fix-by deadlines and the never-scan list; verify the domain |
| Owner | Grant or remove the Owner role; delete the organization |

People only ever see organizations they are a member of: every query is scoped to them, and another
organization's object answers 404, not 403. Superusers see everything.

## Security of the platform itself

- **Sign-in:** short-lived access tokens (30 minutes) with rotating refresh tokens (7 days), optional
  two-factor, and a record of every sign-in and failed attempt.
- **Rate limits** on every endpoint: 1200 requests a minute per signed-in user (`API_RATE_USER`), 120 per
  address without one (`API_RATE_ANON`); tighter on sign-in (5 a minute), password resets (5 an hour) and
  invitation links (30 an hour). Log ingest has its own per-source limit.
- **Secrets at rest:** invitation links, API keys and log ingest keys are stored as hashes; each is shown
  once.
- **Content-Security-Policy** on production builds: no inline scripts, and the page may only talk to itself
  and the API.
- **Outbound requests are guarded:** scan targets and webhook addresses that resolve to private or
  loopback addresses are refused.
- **Dependencies:** CI fails on a known vulnerability in the Python packages or the web app's runtime
  packages (`pip-audit`, `npm audit`); Dependabot opens weekly update pull requests.
- **Audit trail:** the Activity log records who did what and cannot be edited.
- **Browser errors** in the web app are reported to the API and logged like backend errors.
- **Production refuses to start** without `DJANGO_SECRET_KEY`, and turns on domain verification.

## The API

Everything the web app does goes through a REST API, documented at `/api/docs/` (Swagger) and
`/api/redoc/`, with the schema at `/api/schema/`.

```bash
# Sign in (add "otp" when two-factor is on), then use the access token
curl -s -X POST http://localhost:8000/api/auth/login/ \
  -H 'Content-Type: application/json' -d '{"username": "you", "password": "…"}'
curl -H "Authorization: Bearer <access>" "http://localhost:8000/api/organizations/"

# Or a read-only API key (Account settings → API keys), for a SIEM or a CI job
curl -H "Authorization: Api-Key sasm_..." \
  "http://localhost:8000/api/findings/?severity=critical&is_active=true"
```

| Resource | What it is |
|---|---|
| `/api/organizations/` | Organizations, and under each one: `members/`, `invitations/`, `verify-domain/`, `risk-summary/`, `trend/`, `changes/`, `surface-changes/`, `surface-map/`, `fix-plan/`, `heatmap/`, `technologies/`, `services/`, `certificates/`, `hosting/`, `emerging-threats/`, `preflight/`, `getting-started/`, `compliance/`, `activity/`, `report/`, `export/` |
| `/api/assets/` | Hosts; `?q=` takes the search language; `bulk/` imports a list |
| `/api/findings/` | Findings; `triage/`, `assign/`, `comments/`, `timeline/`, `bulk/` |
| `/api/scan-jobs/` | Scans; `trigger/` starts one, `runs/` groups them, `reasons/` explains failures, `progress/` follows a run |
| `/api/scanners/` | The scanners this installation has |
| `/api/surface-policies/`, `/api/saved-views/` | Policies and saved views |
| `/api/notification-rules/` | Alerts and report recipients |
| `/api/log-sources/`, `/api/log-events/`, `/api/log-detections/`, `/api/error-groups/`, `/api/log-alert-rules/` | Logs |
| `/api/ingest/` | Where servers and apps send logs (their own key, not a user's) |
| `/api/auth/…` | Sign-in, profile, password, two-factor, API keys, sign-in history |
| `/health/` | Database and Redis reachable, and the commit that is running |

Lists are paginated (`?page=`), filterable by the fields shown in the docs, and always limited to the
caller's organizations.

## Configuration

Settings are environment variables: `.env` for local development, `.env.production` for
`docker-compose.prod.yml`. Both example files are commented line by line; these are the ones that matter
most.

| Variable | Default | What it does |
|---|---|---|
| `DJANGO_SECRET_KEY` | none | Required whenever `DJANGO_DEBUG` is off |
| `DJANGO_DEBUG` | `False` | `True` for local development only |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Host names the site is served on |
| `DJANGO_HTTPS` | `False` | `True` behind HTTPS: secure cookies, HSTS |
| `CSRF_TRUSTED_ORIGINS`, `CORS_ALLOWED_ORIGINS` | the dev server | The site's own address; the web app's address when it is served from somewhere else |
| `NUM_PROXIES` | `0` | Trusted reverse proxies in front of the API (for the caller's real address) |
| `DATABASE_URL` | none | Postgres. A Neon pooled address is detected and handled |
| `REDIS_URL` | none | Task queue and cache |
| `FRONTEND_URL` | `http://localhost:4200` | Where the web app is: the links in invitation and reset emails |
| `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_USE_TLS`, `DEFAULT_FROM_EMAIL` | print to the log | SMTP for alerts, reports, invitations and password resets |
| `ASM_REQUIRE_DOMAIN_VERIFICATION` | on unless debug | Organizations must prove they control their domain before scanning |
| `ASM_ALLOW_PRIVATE_SCAN_TARGETS` | `False` | Allow scanning hosts on private addresses |
| `ASM_SCREENSHOT_MAX_PAGES` | `6` | Pages the screenshot scanner captures per host |
| `ASM_SCAN_JOB_RETENTION_DAYS` | `90` | Finished scans older than this are deleted nightly (0 keeps them); findings are kept |
| `ASM_SCAN_WORKERS` | `4` | Scans that run at once, for the time estimate before a scan |
| `INVITATION_TTL_DAYS`, `PASSWORD_RESET_TIMEOUT` | `7`, `3600` | How long invitation links (days) and reset links (seconds) last |
| `API_RATE_USER`, `API_RATE_ANON` | `1200/min`, `120/min` | API rate limits |
| `ASM_LOG_INGEST_URL` | none | The address servers and apps send their logs to, shown in the setup steps |
| `DENSIGHT_LOG_KEY` | none | Makes Densight send its own logs to itself (see `.env.example`) |
| `S3_BUCKET`, `S3_ENDPOINT_URL`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | on disk | Keep screenshots in S3-compatible storage (Cloudflare R2, S3) instead of on disk |
| `METRICS_TOKEN` | none | Bearer token Prometheus must send to scrape `/metrics` outside development |
| `DJANGO_SUPERUSER_USERNAME`, `_EMAIL`, `_PASSWORD` | none | The admin account `ensure_admin` creates or updates where there is no shell |

### What runs by itself

`python manage.py setup_periodic_tasks` (run on first setup, and at every start in production) schedules:

| When | What |
|---|---|
| Daily, 02:00 UTC (`--hour` to change) | Every scanner on every organization allowed to scan; the CISA exploited-vulnerabilities list |
| Every 10 minutes | Scans that have run too long are marked failed; the worker reports which scanners it can run; servers and apps that stopped sending logs are flagged |
| Daily, 23:30 UTC | The day's risk snapshot (the trend); risk acceptances that have ended reopen; old logs and old scan records are deleted |
| Mondays, 07:00 UTC | The weekly PDF report |

### Commands

| Command | What it does |
|---|---|
| `setup_periodic_tasks` | Creates or updates the schedule above |
| `load_demo_data --owner <user> [--reset]` | Loads the fictional Acme Retail organization |
| `sync_kev [--file catalogue.json]` | Fetches CISA's exploited-vulnerabilities list now, or loads a downloaded copy |
| `ensure_admin` | Creates the admin from `DJANGO_SUPERUSER_*`, or brings its email and password up to date |

Run them with `docker compose exec api python manage.py <command>`.

## Tests and linting

```bash
# backend: 413 tests (needs the compose stack's db and redis running)
docker compose exec api python manage.py test
cd backend && ruff check .

# frontend: 199 tests
cd frontend
npm run lint
npm test -- --watch=false --browsers=ChromeHeadless
npm run build
```

CI (`.github/workflows/ci.yml`) runs all of it on every pull request, plus `pip-audit` and `npm audit`,
and checks that no model change is missing its migration.

## Deploying

There are three ready-made ways to run it. Whichever you choose: set a real `DJANGO_SECRET_KEY`, serve it
over HTTPS, set `FRONTEND_URL`, and configure SMTP so password resets work.

### 1. Docker Compose on your own server

`docker-compose.prod.yml` is a production-shaped stack: gunicorn, the built web app served by nginx (which
also forwards `/api`, `/admin` and `/health`), the scan worker and scheduler, and only nginx published to
the host. Its database is hosted Postgres ([Neon](https://neon.tech)), so there is no Postgres container;
it reads `.env.production`, not `.env`, so local development and production never share a database.

```bash
# on the server, next to the code
cp .env.production.example .env.production
# fill in: DJANGO_SECRET_KEY, your domain (DJANGO_ALLOWED_HOSTS, CSRF_TRUSTED_ORIGINS,
# FRONTEND_URL, ASM_LOG_INGEST_URL), DATABASE_URL (Neon's pooled connection), SMTP
docker compose -f docker-compose.prod.yml up --build -d
docker compose -f docker-compose.prod.yml exec api python manage.py createsuperuser
```

Migrations, static files and the schedule are set up when the `api` container starts. Put TLS in front of
nginx (a load balancer, Caddy, Cloudflare) and set `DJANGO_HTTPS=True`.

Neon's pooled (`-pooler`) address runs PgBouncer in transaction mode; Densight detects it and turns off
server-side cursors, which that mode can't keep open (`DATABASE_DISABLE_SERVER_SIDE_CURSORS` overrides).

`/metrics` is not exposed through nginx. To scrape it, set `METRICS_TOKEN` and have Prometheus reach
`api:8000` on the compose network with that bearer token.

### 2. Render, free, for a demo

[`render.yaml`](render.yaml) is a Render Blueprint that costs nothing and needs no card: the web app as a
Static Site, **one** free Web Service running the API, the scan worker and the scheduler together
([`backend/start-demo.sh`](backend/start-demo.sh)), and free Key Value as the queue. The database is Neon's
free tier.

Render dashboard → **New → Blueprint** → this repository, then fill in the values it asks for (the site's
address, `DATABASE_URL`, the admin's username, email and password, and email settings if you have them).
At every start the service migrates the database, creates or updates the admin account and reloads the
demo organization.

What the free plan means: the service sleeps after 15 minutes without a request and takes about a minute to
wake; it has 512 MB, so scans run one at a time and the heaviest (nuclei, screenshots) may not fit; and its
disk is wiped at every restart, which is why the demo data is reloaded each time. It is for showing the
product, not for monitoring a real domain.

### 3. Render, production

[`render.production.yaml`](render.production.yaml) is the same stack as separate services: the Static
Site, the API, a Celery worker and Celery beat as Background Workers, and Key Value. Rename it to
`render.yaml` to use it. Two things differ from Docker Compose:

- **Database:** Neon (`DATABASE_URL`, the pooled connection string).
- **Screenshots:** Render services can't share a disk, so the worker stores screenshots in S3-compatible
  storage and the API streams them from there. Cloudflare R2 works well: create a bucket and an API token
  with Object Read & Write, then set `S3_BUCKET`, `S3_ENDPOINT_URL`
  (`https://<account id>.r2.cloudflarestorage.com`), `S3_ACCESS_KEY_ID` and `S3_SECRET_ACCESS_KEY`. The
  bucket stays private.

The worker and beat are paid plans (the worker needs 2 GB for Chromium and nuclei). If Render names the API
anything other than `densight-api.onrender.com`, update the rewrite rules in the blueprint to match.

### The web app on GitHub Pages

The web app can also be served from GitHub Pages while the API runs elsewhere:
`npx ng build --configuration ghpages` builds it for `https://<user>.github.io/sentinel-asm/` and points it
at the API address in `frontend/src/environments/environment.ghpages.ts`. Change that address, and
`baseHref` in `frontend/angular.json`, for your own repository; add the Pages address to the API's
`CORS_ALLOWED_ORIGINS` and set `FRONTEND_URL` to it.

### Deploying on every push

[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) runs on every push to `main`:

1. works out what changed (`backend/`, `frontend/`);
2. runs the whole of CI, and stops if anything fails;
3. **backend changed:** calls Render's deploy hook for exactly that commit, then waits until `/health/`
   reports the new commit is the one running;
4. **frontend changed:** builds the web app and publishes it to GitHub Pages.

To set it up: in Render, open the API service → *Settings → Deploy Hook* and copy the address; in GitHub,
*Settings → Secrets and variables → Actions*, add it as `RENDER_DEPLOY_HOOK_API`; and under
*Settings → Pages*, set the source to **GitHub Actions**. Turn off Render's own auto-deploy so a commit
only goes live after its tests pass.

## How it fits together

```
 Browser (Angular)
      │  HTTPS, JSON
      ▼
 Django API ───── enqueue ────▶ Redis ────▶ Celery worker ──▶ scanner plugins
      │                                          │            (nmap, nuclei, subfinder,
      │                                          │             Chromium, DNS, HTTP, TLS…)
      └────────────────▶ Postgres ◀──────────────┘
                            ▲
 Servers and apps ──────────┤  logs → /api/ingest/
                            │
 Celery beat ───────────────┘  daily scans, snapshots, cleanups, weekly report
```

```
backend/
  apps/
    organizations/   tenants, memberships and roles, invitations, domain verification, saved views, demo data
    assets/          hosts, detected software, hosting detection, the search language
    scanning/        scan jobs, the plugin registry and the 25 plugins, the check before a scan, Celery tasks
    findings/        findings, risk scoring, fix plan, policies, change feed, CISA KEV, compliance, reports
    notifications/   alert rules, email and chat delivery, the weekly report
    logs/            log ingest, parsing, secret masking, detections, error grouping, client libraries
    audit_logs/      sign-in history and the activity log
    api/             REST viewsets, permissions, accounts, two-factor, API keys
  config/            settings, URLs, Celery
  health/            the health check
  Dockerfile.api     Django only
  Dockerfile.worker  adds nmap, subfinder, nuclei and Chromium
frontend/            the Angular app (see frontend/README.md)
docs/                DEMO.md (a demo script) and the screenshots
.github/workflows/   ci.yml (tests, lint, audits) and deploy.yml (deploy on push)
docker-compose.yml        local development
docker-compose.prod.yml   production on one server
render.yaml               free Render demo
render.production.yaml    Render with separate services
```

A few choices worth knowing:

- **One row per finding, for ever.** Scans upsert on (host, what was found). History, "what changed" and
  "came back" all fall out of first-seen, last-seen and resolved-at, with no separate history tables.
- **Scanners know nothing about the database.** They return plain objects; one task reconciles them. That
  keeps a plugin to one file and makes each one testable without a database.
- **Scores are computed, not stored.** A host's grade always reflects its findings as they are now; only
  the daily snapshot for the trend is saved.
- **Organization scoping lives in one place** (`apps/api/permissions.py`), mixed into every viewset.

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| The check before a scan says **no scan worker has checked in** | The `celery-worker` container isn't running, or `setup_periodic_tasks` hasn't been run (the worker reports every 10 minutes and when it starts). `docker compose ps`, then `docker compose restart celery-worker` |
| A scanner is marked **Can't run** | Its program is missing on the worker. The worker image (`Dockerfile.worker`) has nmap, subfinder, nuclei and Chromium; rebuild it with `docker compose build celery-worker` |
| Many scans **skipped** | Those host names no longer exist in DNS. Scan history → open the run → *Why scans didn't finish*. If they are gone for good, add them to the never-scan list |
| **Scanning is disabled** for an organization | Its domain isn't verified. Organization → publish the TXT record → *Check record* |
| Scans stay **pending** | The worker is busy or stopped: `docker compose logs -f celery-worker` |
| No daily scans | Run `setup_periodic_tasks` once and check `celery-beat` is up |
| Invitation or reset emails never arrive | SMTP isn't set, so they are printed to the logs instead. The invitation link is also shown to the admin to copy |
| The web app can't reach the API (CORS errors) | Add the web app's address to `CORS_ALLOWED_ORIGINS` and restart the API |
| `/admin/` sign-in fails over HTTPS with a CSRF error | Add the site's address to `CSRF_TRUSTED_ORIGINS` |
| Hosting shows **Not checked yet** | It is filled in by the *DNS records* scanner; the web response by *Security headers*. Run them once |
| Port 4200 is taken | `npm start -- --port 4300`, and add `http://localhost:4300` to `CORS_ALLOWED_ORIGINS` in `.env` |

## Known limits

- The public-target check runs once before a scanner starts, so it does not stop a host that redirects to
  an internal address mid-scan.
- A root domain can belong to one organization per installation; the first to claim it holds it, even
  unverified.
- Hosting detection covers the common providers by name and published address ranges; it is not a full
  IP-to-network database. Anything else shows as *Not identified*.
- The exploited-vulnerability panel matches by product name, because scans rarely see exact versions:
  treat a match as "check your version" unless a scan has confirmed the CVE.
- Log events are stored in Postgres, which suits tens of servers and apps; much larger volumes want a
  dedicated log store.
- With Docker Compose, screenshots are on a volume shared by the worker and the API, which ties both to one
  host. Use the S3 settings before running workers on more than one machine.
- Compliance mappings are indicative. They show which controls the open issues relate to; they are not an
  assessment.
- Some internal names still carry the project's first name, Sentinel ASM: the repository, the
  `_sentinel-asm` verification record and the `sasm_` API key prefix. Changing them would break records
  and keys already in use.

## Brand

The logo is a D whose bowl holds a radar eye: the sweep, the pupil, and one exposure found (in amber). The
files are in [`frontend/public/brand/`](frontend/public/brand/): `mark.svg` (the square mark),
`logo-light.svg` and `logo-dark.svg` (mark and name) and `og-image.png` (shown when a link is shared). The
browser icons are in `frontend/public/`.
