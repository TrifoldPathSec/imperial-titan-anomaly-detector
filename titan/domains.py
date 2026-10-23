"""Reduce a DNS name to the domain someone registered.

`img-03.cdn.example.co.uk` and `api.cdn.example.co.uk` both become
`example.co.uk`, so a device that rotates subdomains doesn't alert on every
lookup. A full public suffix list is overkill here; the short list below
covers the common two-part suffixes.
"""

from __future__ import annotations

import ipaddress

TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr",
    "com.br", "com.mx", "com.ar", "com.co", "com.tr", "com.cn", "net.cn",
    "org.cn", "com.hk", "com.sg", "com.tw", "co.in", "co.za", "co.il",
    "com.es", "com.pl", "gob.mx",
    # Hosting platforms where each subdomain is a different owner
    "github.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
    "amazonaws.com", "appspot.com", "netlify.app", "vercel.app", "pages.dev",
    "workers.dev", "ngrok.io", "ngrok-free.app", "duckdns.org", "no-ip.org",
}


def registrable(name: str | None, ignore: tuple[str, ...] = ()) -> str | None:
    """Return the registrable domain, or None for names that shouldn't alert."""
    if not name:
        return None
    name = name.strip().rstrip(".").lower()
    if not name or "." not in name:
        return None  # single-label names stay on the LAN
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    labels = name.split(".")
    for suffix in ignore:
        if name == suffix or name.endswith("." + suffix):
            return None
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
