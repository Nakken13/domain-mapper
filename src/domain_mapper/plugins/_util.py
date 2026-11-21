"""Small helpers shared by several plugins.

Traffic: none. Pure functions over strings and addresses.
"""

from __future__ import annotations

import ipaddress
import re

_COUNTRY = re.compile(r"^[A-Za-z]{2}$")


def country_code(raw: str) -> str | None:
    """`raw` if it is a two-letter country code, else None (unrouted ranges say "None")."""
    return raw if _COUNTRY.match(raw) else None


def is_public_ip(address: str) -> bool:
    """True for a globally routable address: private ranges never leave the machine."""
    return ipaddress.ip_address(address).is_global
