"""
Plain-language context for a finding: why it matters and what to do
about it. A scanner says "Open port 3389/tcp"; the person deciding
whether to act needs "remote desktop is reachable from the internet,
which is a common way in for ransomware -- put it behind a VPN".

Derived from the finding's type and raw data on the way out, not
stored, so improving the wording improves every existing finding too.
Pure functions with no database access.
"""

from .models import Finding

GENERIC_PORT = (
    "A network service on this host answers connections from anywhere on the internet. "
    "Every exposed service is something an attacker can probe for weaknesses.",
    "Confirm this service is meant to be public. If it is not, close the port or restrict it "
    "to known addresses with a firewall or security group.",
)

# port -> (why it matters, how to fix)
PORT_GUIDANCE = {
    "21": (
        "FTP sends usernames, passwords and files unencrypted, so anyone on the network path can read them.",
        "Replace FTP with SFTP or FTPS, or close the port if file transfer is no longer needed.",
    ),
    "22": (
        "SSH gives command-line control of the server. Exposed to the internet it is constantly "
        "targeted by automated password guessing.",
        "Allow key-based logins only, disable password and root login, and restrict the port to "
        "a VPN or known addresses where possible.",
    ),
    "23": (
        "Telnet gives command-line control of the device with no encryption at all: passwords "
        "cross the network in plain text.",
        "Disable Telnet and use SSH instead.",
    ),
    "25": (
        "A mail server is reachable. If it relays mail for anyone, it can be abused to send spam "
        "and phishing in your name.",
        "Make sure it does not relay for unauthenticated senders, and close it if this host is "
        "not supposed to receive mail.",
    ),
    "3306": (
        "A MySQL database is reachable from the internet. Databases should never be directly "
        "exposed: a weak password or an unpatched flaw gives away all the data in it.",
        "Block the port from the internet and let only the application servers connect, over a "
        "private network.",
    ),
    "5432": (
        "A PostgreSQL database is reachable from the internet. Databases should never be "
        "directly exposed: a weak password or an unpatched flaw gives away all the data in it.",
        "Block the port from the internet and let only the application servers connect, over a "
        "private network.",
    ),
    "6379": (
        "A Redis server is reachable from the internet. Redis often runs without a password, "
        "which lets anyone read or wipe its data and in some setups take over the server.",
        "Block the port from the internet, bind Redis to a private address and require a password.",
    ),
    "3389": (
        "Remote Desktop is reachable from the internet. Exposed RDP is one of the most common "
        "ways ransomware groups get into a network.",
        "Take RDP off the internet: put it behind a VPN or a remote-access gateway and require "
        "multi-factor authentication.",
    ),
    "8000": GENERIC_PORT,
}

WEB_PORTS = {"80", "443", "8080", "8443"}

HEADER_GUIDANCE = {
    "Strict-Transport-Security": (
        "Without HSTS a browser can be tricked into using an unencrypted connection, letting "
        "someone on the same network read or change what the visitor sees.",
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response.",
    ),
    "Content-Security-Policy": (
        "Without a Content Security Policy the browser runs any script injected into the page, "
        "which makes cross-site scripting flaws far more damaging.",
        "Add a Content-Security-Policy header that lists the sources scripts and styles may load from. "
        "Start in report-only mode to see what it would block.",
    ),
    "X-Content-Type-Options": (
        "Without this header a browser may guess a file's type and run an uploaded file as a script.",
        "Send `X-Content-Type-Options: nosniff`.",
    ),
    "X-Frame-Options": (
        "Without this header another site can load this page invisibly in a frame and trick "
        "visitors into clicking things on it (clickjacking).",
        "Send `X-Frame-Options: DENY` (or `SAMEORIGIN`), or use the `frame-ancestors` directive in a "
        "Content Security Policy.",
    ),
    "Referrer-Policy": (
        "Without a referrer policy the full address of the page a visitor came from is sent to "
        "other sites, which can leak internal URLs or tokens in them.",
        "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
    ),
}

# For the scanners that label each result with a `check` code in raw_data.
CHECK_GUIDANCE = {
    # --- email spoofing protection ---
    "spf_missing": (
        "Without SPF, receiving mail servers cannot tell your real mail servers from an impostor's.",
        "Publish a TXT record on the domain listing the servers that send your mail, ending in "
        "`-all`. If the domain sends no email at all, publish `v=spf1 -all`.",
    ),
    "spf_multiple": (
        "With more than one SPF record, receivers discard them all, so the domain is effectively unprotected.",
        "Merge them into a single `v=spf1` record.",
    ),
    "spf_allows_anyone": (
        "This SPF record tells the world that any server may send email as your domain, which "
        "is the opposite of what SPF is for.",
        "Replace `+all` with `-all` (or `~all` while testing) after listing your real mail servers.",
    ),
    "spf_neutral": (
        "A neutral SPF result gives receivers no reason to distrust forged mail.",
        "Change `?all` to `~all`, then `-all` once you are sure every legitimate sender is listed.",
    ),
    "spf_no_all": (
        "Without a closing rule, mail from servers you did not list is not marked as suspicious.",
        "End the record with `-all` (or `~all` while testing).",
    ),
    "dmarc_missing": (
        "Anyone can send email that shows your domain in the From line, and most recipients' "
        "mail systems will deliver it. This is how invoice fraud and phishing in a company's "
        "name are done.",
        "Publish a TXT record at `_dmarc.<your domain>`. Start with "
        "`v=DMARC1; p=none; rua=mailto:<a mailbox you read>` to collect reports, then move to "
        "`p=quarantine` and `p=reject`.",
    ),
    "dmarc_multiple": (
        "With more than one DMARC record, receivers ignore DMARC completely.",
        "Keep exactly one `v=DMARC1` record at `_dmarc.<your domain>`.",
    ),
    "dmarc_monitor_only": (
        "The domain is watching for forged email but not stopping it: messages that fake your "
        "address are still delivered.",
        "Review the DMARC reports to confirm your legitimate mail passes, then change the policy "
        "to `p=quarantine` and finally `p=reject`.",
    ),
    "dmarc_partial": (
        "Part of the forged mail sent in your name is exempt from the policy and still gets delivered.",
        "Raise `pct` to 100 once the reports show legitimate mail is unaffected.",
    ),
    "dkim_not_found": (
        "DKIM lets receivers verify a message really came from you and was not altered. This "
        "result only means it could not be confirmed from outside, not that it is absent.",
        "Check with your mail provider that DKIM signing is switched on for this domain.",
    ),
    # --- subdomain takeover ---
    "takeover": (
        "Someone else can register the abandoned address and put their own content on your "
        "subdomain: a convincing phishing page on your real domain, able to read cookies "
        "scoped to it.",
        "Delete the DNS record for this subdomain, or re-create the resource at the provider "
        "so the name is yours again. Remove DNS records as part of shutting any service down.",
    ),
    "dangling_cname": (
        "The record points at something that no longer exists. If the target name ever becomes "
        "available to register, whoever takes it controls this subdomain.",
        "Delete the DNS record if the service is gone, or point it at the right target.",
    ),
    # --- TLS configuration ---
    "old_protocol": (
        "TLS 1.0 and 1.1 have known weaknesses that let a well-placed attacker read or tamper "
        "with traffic. Security standards such as PCI DSS forbid them.",
        "Disable TLS 1.0 and 1.1 in the web server or load balancer and allow only TLS 1.2 and 1.3.",
    ),
    "no_modern_protocol": (
        "The site can only be reached over encryption that is considered broken, and current "
        "browsers will refuse to open it at all.",
        "Upgrade the server or its TLS library and enable TLS 1.2 and 1.3.",
    ),
    "no_tls13": (
        "TLS 1.2 is still acceptable. TLS 1.3 is faster and removes older, weaker options.",
        "Enable TLS 1.3 when the server software supports it. No urgency.",
    ),
    "untrusted_certificate": (
        "Visitors see a full-page security warning, and people who click through it are "
        "trained to ignore the one warning that would protect them from a real interception.",
        "Install a certificate from a trusted authority that covers this exact hostname, "
        "including the intermediate certificates.",
    ),
    # --- outdated software ---
    "end_of_life": (
        "Software past its end of life no longer gets security fixes, so every vulnerability "
        "found in it from now on stays open. Attackers scan for exactly these version numbers.",
        "Upgrade to a supported release. If the server is patched by its operating system "
        "vendor and only the reported number is old, hide the version header to avoid the noise.",
    ),
    # --- exposed files ---
    "git_exposed": (
        "Anyone can download the site's entire source code and its history, including any "
        "passwords, API keys or customer data that were ever committed.",
        "Block access to `/.git` in the web server now, then treat every secret that was ever "
        "in the repository as leaked and change it. Deploy built files, not the repository.",
    ),
    "env_exposed": (
        "This file normally holds the application's database password, API keys and signing "
        "secrets. Anyone can read them with one request.",
        "Remove the file from the web root or block it in the web server, then change every "
        "secret it contained: they must be assumed stolen.",
    ),
    "config_backup_exposed": (
        "A backup copy of a configuration file is served as plain text, database password included.",
        "Delete the backup from the server and change the database password it contained.",
    ),
    "database_dump_exposed": (
        "A copy of the database can be downloaded by anyone: customer records, password hashes "
        "and everything else in it. This is a data breach waiting to be noticed.",
        "Remove the file immediately, check the access logs for downloads, and follow your "
        "breach-notification obligations if it held personal data.",
    ),
    "phpinfo_exposed": (
        "This page lists the server's exact software versions, file paths and configuration, "
        "which tells an attacker precisely which weaknesses to try.",
        "Delete the file. It is a debugging aid that should not exist on a live server.",
    ),
    "server_status_exposed": (
        "The status page shows the requests the server is handling right now, including "
        "visitors' addresses and the URLs they are opening.",
        "Restrict `/server-status` to localhost or disable the status module.",
    ),
    # --- DNS zone transfer ---
    "zone_transfer_allowed": (
        "The nameserver gives your complete list of hostnames to anyone. That includes internal "
        "and forgotten systems an attacker would otherwise have to guess at.",
        "Restrict zone transfers on this nameserver to your secondary nameservers' addresses only.",
    ),
    # --- CORS ---
    "cors_any_origin_with_credentials": (
        "Any website a logged-in user visits can make requests to this site as that user and "
        "read the answers: account details, messages, anything the user can see.",
        "Only send `Access-Control-Allow-Origin` for an explicit list of sites you trust. "
        "Never echo back the request's Origin header together with `Allow-Credentials: true`.",
    ),
    "cors_null_origin_with_credentials": (
        "Pages running in a sandbox, or opened from a file, present the origin 'null'. Trusting "
        "it with credentials lets such a page act as the logged-in user.",
        "Remove `null` from the allowed origins.",
    ),
    "cors_any_origin": (
        "Without cookies this only exposes content that is public anyway, but it usually means "
        "the allow-list is not doing its job and may become dangerous if credentials are added.",
        "Replace the echo with an explicit list of allowed origins, or `*` if the content is public.",
    ),
    # --- cookies ---
    "session_cookie_flags": (
        "A session cookie identifies a logged-in visitor. Without these flags it can be read "
        "by an injected script or sent over an unencrypted connection, and whoever gets it is "
        "logged in as that person.",
        "Set the cookie with `Secure; HttpOnly; SameSite=Lax` (or `Strict`) in the application "
        "or framework's session settings.",
    ),
    "cookie_flags": (
        "The cookie is less protected than it could be. The risk depends on what it holds.",
        "Add the missing flags unless the cookie genuinely needs to be read by scripts or "
        "sent across sites.",
    ),
    # --- HTTPS enforcement ---
    "http_only": (
        "Everything visitors send and receive, including passwords, travels unencrypted and "
        "can be read or changed by anyone on the same network. Browsers mark the site 'Not secure'.",
        "Install a TLS certificate (Let's Encrypt is free) and serve the site over HTTPS.",
    ),
    "no_https_redirect": (
        "Visitors who arrive by the plain-HTTP address stay on it, so their traffic can be read "
        "or altered on the way even though an HTTPS version exists.",
        "Make the HTTP address return a permanent redirect to HTTPS, and add an HSTS header so "
        "browsers stop trying HTTP at all.",
    ),
    # --- security.txt ---
    "security_txt_missing": (
        "Someone who finds a weakness in your systems has no stated way to tell you. Reports "
        "that cannot be delivered are often dropped, or published instead.",
        "Publish `/.well-known/security.txt` with at least a `Contact:` line (an email address "
        "or form) and an `Expires:` date. securitytxt.org generates one.",
    ),
    "security_txt_no_contact": (
        "Without a contact the file does not do its one job.",
        "Add a `Contact:` line with an email address or a reporting form.",
    ),
    "lookalike_mail": (
        "Someone has registered a domain that looks like yours and set it up to send and receive "
        "email. That is how invoice fraud and phishing in your name usually start: staff, customers "
        "and suppliers see a familiar name and trust the message.",
        "Check who owns it (a WHOIS lookup). If it's yours, mark this as an accepted risk. If not, "
        "warn staff and finance, block it at your email gateway, and ask the registrar to take it "
        "down or file a UDRP complaint. A strict DMARC policy on your own domain also helps.",
    ),
    "lookalike_web": (
        "Someone has registered a domain that looks like yours and pointed it at a server. It may be "
        "parked, but it could host a copy of your site to collect passwords or card details.",
        "Check who owns it and what it shows. If it's yours, mark this as an accepted risk. If it "
        "imitates your site, report it to the registrar and hosting provider for takedown, and "
        "block it on your network.",
    ),
    "security_txt_expired": (
        "An expired file tells researchers the details may be stale, so they may not use them.",
        "Update the `Expires:` date (a year ahead is typical) and confirm the contact still works.",
    ),
}

NOTHING = {"impact": "", "remediation": ""}


def guidance_for(finding) -> dict[str, str]:
    """Returns {"impact": ..., "remediation": ...}; both empty for
    inventory findings, which describe what exists rather than a problem."""
    raw = finding.raw_data or {}
    kind = finding.finding_type

    if kind == Finding.FindingType.OPEN_PORT:
        port = str(raw.get("port", ""))
        if port in WEB_PORTS:
            impact, fix = (
                "A web server is reachable here. That is expected for a website; it matters only "
                "if this host is not supposed to serve one.",
                "No action needed if this is a public site. Otherwise take it offline or restrict access.",
            )
        else:
            impact, fix = PORT_GUIDANCE.get(port, GENERIC_PORT)
    elif kind == Finding.FindingType.MISSING_HEADER:
        impact, fix = HEADER_GUIDANCE.get(
            str(raw.get("header", "")),
            (
                "A recommended security header is missing, which removes a layer of browser protection.",
                "Add the header in the web server or application configuration.",
            ),
        )
    elif kind == Finding.FindingType.EXPIRED_SSL:
        days = raw.get("days_remaining")
        if isinstance(days, int) and days < 0:
            impact, fix = (
                "The certificate has expired. Browsers now show visitors a full-page security "
                "warning, and anything that calls this site automatically will fail.",
                "Renew and install the certificate now, then set up automatic renewal.",
            )
        else:
            impact, fix = (
                "When this certificate expires, browsers will show visitors a full-page security "
                "warning and automated connections to the site will fail.",
                "Renew the certificate before it expires, and set up automatic renewal "
                "(for example with Let's Encrypt) so it does not depend on someone remembering.",
            )
    elif kind in (Finding.FindingType.NUCLEI_MATCH, Finding.FindingType.EXPOSED_SERVICE):
        impact, fix = (
            "The scanner matched a known vulnerability or misconfiguration on this host. "
            "Known issues are the ones attackers look for first, because the method is public.",
            "Read the finding's description and references, apply the vendor's patch or configuration "
            "change, then run the scan again to confirm the finding is gone.",
        )
    elif raw.get("check") in CHECK_GUIDANCE:
        impact, fix = CHECK_GUIDANCE[raw["check"]]
    else:
        return dict(NOTHING)

    return {"impact": impact, "remediation": fix}
