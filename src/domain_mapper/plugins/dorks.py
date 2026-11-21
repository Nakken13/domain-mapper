"""Google dork links for a scope domain, for the user to open by hand.

Traffic: none. This module only builds search URLs; it never runs a search, so no
automated query reaches Google (whose terms forbid them) or the target. It is a plain
function, not a registered collection plugin, and its output never enters the graph.

Templates adapted from the `site` mode of dorkint (MIT, Copyright (c) 2026 Nakken13,
sibling project of the same author). Only attack-surface categories are kept: no
template hunts credentials (`DB_PASSWORD`, `wp-config`…), injection points (`?id=`) or
people (emails, contacts, job offers).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote_plus

from domain_mapper.plugins.base import ScopeView

SEARCH_URL = "https://www.google.com/search?q="

CATEGORIES: dict[str, tuple[str, ...]] = {
    "Subdomains": (
        "site:*.{domain} -www",
        "site:*.*.{domain} -www",
        "site:*.{domain} -site:www.{domain}",
    ),
    "Staging and remote access": (
        "site:*.{domain} (inurl:dev OR inurl:staging OR inurl:test OR inurl:preprod OR inurl:beta)",
        "site:*.{domain} (inurl:vpn OR inurl:mail OR inurl:webmail OR inurl:remote)",
    ),
    "Login and admin pages": (
        "site:{domain} inurl:login",
        "site:{domain} inurl:admin",
        "site:*.{domain} (intitle:login OR intitle:admin OR intitle:portal)",
        "site:{domain} (inurl:signin OR inurl:dashboard OR inurl:portal)",
    ),
    "Exposed documents": (
        "site:{domain} filetype:pdf",
        "site:{domain} filetype:doc OR filetype:docx",
        "site:{domain} filetype:xls OR filetype:xlsx",
        "site:{domain} filetype:ppt OR filetype:pptx",
        "site:{domain} (ext:xml OR ext:json OR ext:yml OR ext:yaml)",
    ),
    "Directory listings": (
        'site:{domain} intitle:"index of"',
        'site:{domain} intitle:"index of" "parent directory"',
        'site:{domain} intitle:"index of" (ext:zip OR ext:tar OR ext:gz OR ext:7z)',
        'site:{domain} (inurl:upload OR inurl:uploads OR inurl:files) intitle:"index of"',
        'site:{domain} intitle:"index of" (filetype:sql OR filetype:log OR filetype:bak)',
        'site:{domain} (ext:git OR ext:svn) intitle:"index of"',
    ),
    "Error pages and technologies": (
        'site:{domain} "page not found" OR "page introuvable"',
        'site:{domain} "powered by"',
        'site:{domain} ("powered by WordPress" OR "powered by Joomla" OR "powered by Drupal")',
        'site:{domain} (inurl:swagger OR inurl:api-docs OR intitle:"swagger")',
        'site:{domain} intitle:"phpinfo()"',
    ),
    "Cloud storage mentions": (
        'site:s3.amazonaws.com "{domain}"',
        'site:blob.core.windows.net "{domain}"',
        'site:storage.googleapis.com "{domain}"',
    ),
}


@dataclass(frozen=True)
class Dork:
    category: str
    query: str
    url: str


def generate_dorks(domain: str, scope: ScopeView) -> list[Dork]:
    """Dork links for `domain`, refused (OutOfScopeError) when it is not authorized."""
    authorized = scope.require(domain)
    return [
        Dork(category, query, SEARCH_URL + quote_plus(query))
        for category, templates in CATEGORIES.items()
        for query in (template.format(domain=authorized) for template in templates)
    ]
