# Demo script

A 12-minute walkthrough of Densight for a client, with what to click,
what to say, and honest answers to the questions people usually ask.

## Before the meeting

1. Start the stack and bring the database up to date:

   ```bash
   docker compose up -d
   docker compose exec api python manage.py migrate
   docker compose exec api python manage.py setup_periodic_tasks
   ```

2. Load the demo organization (fictional, on a domain that doesn't exist):

   ```bash
   docker compose exec api python manage.py load_demo_data --owner <your username> --reset
   ```

3. Open the app, sign in, and pick **Acme Retail** in the organization switcher.
4. Choose light or dark mode at the bottom of the sidebar, whichever suits the room.
5. Optional: have a domain you own already added and verified if you want
   to show a live scan. **Don't press Run scan on Acme Retail** — its
   domain doesn't exist, so live scans of it just fail.

## The one-sentence pitch

> Densight continuously finds everything an organization exposes to the
> internet, checks it for the weaknesses attackers look for first, and
> tells the right people what to fix, by when — in plain language.

## Why it matters (what to say before clicking)

- **You can't protect what you don't know you have.** Over time every
  organization accumulates forgotten hosts: old campaign sites, test
  servers, a subdomain set up for a supplier. Attackers find them with
  the same free tools Densight uses.
- **Exposure changes daily.** A certificate expires, a database port is
  opened "for a quick test", someone uploads a backup to the web server.
  An annual penetration test sees one day a year; this looks every day.
- **Raw scanner output doesn't get things fixed.** "Open port 3389"
  means nothing to the person who has to approve the work. Densight
  says *why* it matters, *what* to do, *who* owns it and *by when*.

## The walkthrough

About 12 minutes. The first half is the story (what's wrong, what to do
first); the second half is how the team works with it.

| # | Screen | Do | Say |
|---|---|---|---|
| 1 | **Board view** (dashboard → *Board view* → *Full screen*) | Open it before the client sits down; leave it on the screen. | "This is what the security team's wall screen shows: live, refreshed every minute." |
| 2 | **Dashboard** | Read the **In short** box aloud. | "This is the whole picture in a few sentences, written from the data, not by a person." |
| 3 | Dashboard | Point at the **grade (C)** and the **90-day trend**. | "Three months ago they were a D. The grade is held at C because critical issues are still open: one exposed database is enough, however tidy the rest is." |
| 4 | Dashboard | Scroll to **Grade, day by day** and **Where the risk is**; click the darkest square. | "Three months in one picture. And this grid shows where the risk is concentrated; one click to the findings behind it." |
| 5 | Bell next to the logo | Open it. | "What the team did lately; anything assigned to me is marked." |
| 6 | **Fix plan** (or the link under the grade) | Read the three lines at the top, then open step 2's hosts. | "This answers 'what do we do on Monday?'. Fix these three and you're a B; get through step ten and you're an A. The plan puts crown-jewel systems first." |
| 7 | Fix plan | **Assign all to…** on a step. | "One click hands a whole fix to the person who owns it." |
| 8 | **Findings** → *Database dump is publicly downloadable* → **History & comments** | Show **Why it matters**, **How attackers use this**, then the discussion on the right. | "Critical: anyone can download the database. It names the attacker technique, MITRE ATT&CK T1552. And here's the team working it: found, assigned, logs checked, incident opened. All in one place." |
| 9 | **My work** | Point at the badge in the sidebar. | "Each person sees their own list by deadline. Two of mine are overdue." |
| 10 | **Findings** | Tick three rows; show the bulk bar. Then filter **Came back after a fix**. | "Triage in bulk. And this one, the Postgres port, was closed in September and came back when a server was rebuilt. Fixes that don't stick get flagged." |
| 11 | **Assets** → *shop* | Show **Crown jewel**, the labels, and **Re-check this host** (don't press it on the demo). | "The scanner can't know what matters to the business; you tell it once. After a fix, one button re-checks the host to prove it." |
| 12 | **Inventory** → Software, Open services, Certificates | Type `apache` in Software; open Certificates. | "The morning a new vulnerability is announced, the question is 'where do we run that?'. Here's the answer, and every certificate by expiry date." |
| 13 | **Findings** → *Lookalike domain registered: acmeretail.example* | Show the description. | "Someone registered our name without the hyphen and set it up for email. That's how invoice fraud starts." |
| 14 | **Compliance** → **MITRE ATT&CK** card | Click it; **View issues** on T1190. | "The same issues seen by auditors (OWASP, CIS, ISO, PCI) and by attackers (ATT&CK)." |
| 15 | **Organization** | Scroll to **Fix-by deadlines** and **Never scan**. | "Your policy, not ours: how fast each severity must be fixed. And the hosts run by suppliers, which we must not test, are never scanned." |
| 16 | **Account settings** | Show **Two-factor sign-in**, **API keys**, **Recent sign-ins**. | "A security tool has to be secure itself: two-factor sign-in, read-only API keys for your SIEM, and a record of every sign-in." |
| 17 | **Alerts & reports** | Read the two tiles at the top; press **Add an alert** and show the three questions and the sentence at the bottom; then **Send test** on the Slack alert. | "Two things: an alert the moment a scan finds something new (once, not every day), and a one-page report every Monday for people who never log in. Setting one up is three questions, and it tells you how many alerts it would have sent last month." |
| 18 | Anywhere | Press **Ctrl+K**, type `cert`. Then press **?**. | "Anything (a host, an issue, a page) in two keystrokes, and shortcuts for people who live in the tool." |
| 19 | **Scanners** *(own domain only)* | **Run all scanners**. | "Eighteen checks, from exposed files to lookalike domains, across every host, then daily by themselves." |

## Questions you'll probably get

**Is it safe and legal to scan with this?**
It only scans domains the organization proves it owns (a DNS record,
checked on the Organization page), and it refuses targets that resolve
to private or internal addresses. Only scan what you're authorized to test.

**How is this different from a penetration test?**
A pen test is a person trying to break in on a given week. Densight is
continuous and automated: it finds what exists and what has changed,
every day. They complement each other; this doesn't replace one.

**And from a vulnerability scanner?**
A vulnerability scanner checks the list you give it. Densight first
*discovers* the list — including hosts nobody knew about — then
prioritizes, assigns and tracks the fixes.

**What about false positives?**
Anyone with the Analyst role can mark a finding as a false positive or
an accepted risk, with a reason. It stops counting toward the grade,
stays on record in the Activity log, and survives future scans.

**Does it make us compliant with ISO 27001 / PCI DSS?**
No, and it says so on the page. The mapping shows which controls the
open issues relate to, which helps prioritise and gives evidence of
monitoring. Compliance is a wider assessment.

**How does it fit our tools?**
Email and chat alerts (Slack, Teams, Mattermost via webhook), a weekly
PDF, CSV/JSON/PDF exports, copy-as-ticket, and a documented REST API
(`/api/docs/`) with read-only API keys for a SIEM or a CI pipeline.

**How is the tool itself protected?**
Two-factor sign-in, roles (viewer to owner), API keys that can only read,
a sign-in history for each person, and an activity log of every
decision. It only scans domains you have proved you own.

**Can it help with phishing?**
Partly. It checks SPF, DKIM and DMARC (whether someone can send email as
your domain) and finds registered lookalike domains (whether someone can
send email from a domain that looks like yours). It does not read or
filter email.

**Some of our subdomains are run by suppliers. Will you scan them?**
Not if you list them under **Never scan** on the Organization page. They
stay in the inventory, but no scanner touches them.

**Where does our data live?**
It is self-hosted: it runs in your own environment with Docker, and
nothing is sent to a third party.

## Don't overclaim

- It doesn't confirm that a weakness can actually be exploited; it
  reports what it detects.
- DKIM can only be guessed at from outside; that result is informational.
- Outdated-software detection relies on versions servers announce, which
  many hide.
- The compliance and ATT&CK views are an indicative mapping, not an audit.
- Lookalike detection checks a few hundred common variations, not every
  possible domain, and can't tell who owns one; a domain your company
  registered defensively should be marked as an accepted risk.
- The fix plan's grade projection assumes each fix closes the issues as
  listed; the real grade moves when the next scan confirms it.
