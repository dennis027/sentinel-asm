"""
Who hosts a site, worked out from what scans already see: the names it
points at (CNAME), the reverse DNS of its addresses, a few well-known
address ranges and the Server header. Nothing here makes a request.

Good enough to answer "how much of us is on Cloudflare / AWS / Vercel"
and "what's still on the old datacenter"; not a full IP-to-ASN database.
"""

import ipaddress

# (suffix of a CNAME target or reverse-DNS name, provider)
NAME_SUFFIXES = [
    ("cloudfront.net", "AWS"),
    ("amazonaws.com", "AWS"),
    ("awsglobalaccelerator.com", "AWS"),
    ("azurewebsites.net", "Azure"),
    ("azureedge.net", "Azure"),
    ("azurefd.net", "Azure"),
    ("cloudapp.azure.com", "Azure"),
    ("cloudapp.net", "Azure"),
    ("trafficmanager.net", "Azure"),
    ("blob.core.windows.net", "Azure"),
    ("googleusercontent.com", "Google Cloud"),
    ("appspot.com", "Google Cloud"),
    ("run.app", "Google Cloud"),
    ("googlehosted.com", "Google Cloud"),
    ("cdn.cloudflare.net", "Cloudflare"),
    ("pages.dev", "Cloudflare"),
    ("workers.dev", "Cloudflare"),
    ("fastly.net", "Fastly"),
    ("fastlylb.net", "Fastly"),
    ("akamaiedge.net", "Akamai"),
    ("akamaized.net", "Akamai"),
    ("edgekey.net", "Akamai"),
    ("edgesuite.net", "Akamai"),
    ("vercel-dns.com", "Vercel"),
    ("vercel.app", "Vercel"),
    ("netlify.app", "Netlify"),
    ("netlify.com", "Netlify"),
    ("github.io", "GitHub Pages"),
    ("herokuapp.com", "Heroku"),
    ("herokudns.com", "Heroku"),
    ("onrender.com", "Render"),
    ("fly.dev", "Fly.io"),
    ("digitaloceanspaces.com", "DigitalOcean"),
    ("ondigitalocean.app", "DigitalOcean"),
    ("linodeusercontent.com", "Akamai (Linode)"),
    ("your-server.de", "Hetzner"),
    ("hetzner.com", "Hetzner"),
    ("ovh.net", "OVHcloud"),
    ("myshopify.com", "Shopify"),
    ("shopify.com", "Shopify"),
    ("wpengine.com", "WP Engine"),
    ("squarespace.com", "Squarespace"),
    ("wixdns.net", "Wix"),
    ("zendesk.com", "Zendesk"),
    ("hubspot.net", "HubSpot"),
]

# Published ranges for the providers whose addresses don't reverse-resolve
# to their own names (Cloudflare's proxies, Fastly's edge).
ADDRESS_RANGES = [
    (ipaddress.ip_network(cidr), provider)
    for cidr, provider in [
        ("173.245.48.0/20", "Cloudflare"), ("103.21.244.0/22", "Cloudflare"),
        ("103.22.200.0/22", "Cloudflare"), ("103.31.4.0/22", "Cloudflare"),
        ("141.101.64.0/18", "Cloudflare"), ("108.162.192.0/18", "Cloudflare"),
        ("190.93.240.0/20", "Cloudflare"), ("188.114.96.0/20", "Cloudflare"),
        ("197.234.240.0/22", "Cloudflare"), ("198.41.128.0/17", "Cloudflare"),
        ("162.158.0.0/15", "Cloudflare"), ("104.16.0.0/13", "Cloudflare"),
        ("104.24.0.0/14", "Cloudflare"), ("172.64.0.0/13", "Cloudflare"),
        ("131.0.72.0/22", "Cloudflare"), ("2606:4700::/32", "Cloudflare"),
        ("151.101.0.0/16", "Fastly"), ("199.232.0.0/16", "Fastly"),
        ("76.76.21.0/24", "Vercel"),
        ("185.199.108.0/22", "GitHub Pages"),
    ]
]

# Server header (lower-case, prefix) -> provider.
SERVER_HEADERS = [
    ("cloudflare", "Cloudflare"),
    ("amazons3", "AWS"),
    ("cloudfront", "AWS"),
    ("awselb", "AWS"),
    ("vercel", "Vercel"),
    ("netlify", "Netlify"),
    ("github.com", "GitHub Pages"),
    ("gws", "Google Cloud"),
    ("google frontend", "Google Cloud"),
    ("akamaighost", "Akamai"),
    ("microsoft-azure", "Azure"),
    ("windows-azure", "Azure"),
]


def _by_name(name: str) -> str:
    name = name.lower().rstrip(".")
    for suffix, provider in NAME_SUFFIXES:
        if name == suffix or name.endswith("." + suffix):
            return provider
    return ""


def _by_address(address: str) -> str:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return ""
    for network, provider in ADDRESS_RANGES:
        if ip.version == network.version and ip in network:
            return provider
    return ""


def detect_provider(cnames=(), reverse_names=(), addresses=(), server: str = "") -> str:
    """The most specific answer the evidence gives, or "" when it says nothing."""
    for name in cnames:
        if provider := _by_name(name):
            return provider
    for address in addresses:
        if provider := _by_address(address):
            return provider
    for name in reverse_names:
        if provider := _by_name(name):
            return provider
    server = (server or "").strip().lower()
    for prefix, provider in SERVER_HEADERS:
        if server.startswith(prefix):
            return provider
    return ""


def refresh_provider(asset) -> None:
    """Recomputes asset.hosting["provider"] from everything known about it (not saved)."""
    hosting = dict(asset.hosting or {})
    provider = detect_provider(
        hosting.get("cnames", []),
        hosting.get("reverse_names", []),
        hosting.get("ips", []),
        (asset.web or {}).get("server", ""),
    )
    if provider:
        hosting["provider"] = provider
    else:
        hosting.pop("provider", None)
    asset.hosting = hosting
