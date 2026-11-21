"""DNS resolution behind a small interface, so DNS plugins are tested offline.

Traffic: DNS queries to the system's configured recursive resolver only (dnspython
reads the OS configuration). The resolver, not SurfaceMap, talks to the authoritative
servers; nothing is sent to the target over any other protocol.

`answer_from_message` turns a dnspython `Message` into plain records: every owner name is
kept, so a CNAME chain stays visible (which name actually owns an A record decides the
reach of that IP), and an NXDOMAIN answer still carries the dangling chain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

import dns.asyncresolver
import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver

Rcode = Literal["NOERROR", "NXDOMAIN"]


class DnsError(Exception):
    """A lookup failed (timeout, SERVFAIL, refused…): neither an answer nor a denial."""


@dataclass(frozen=True)
class ResourceRecord:
    owner: str
    type: str
    value: str
    """Flattened rdata: an address, a target name (no final dot), or the TXT text."""


@dataclass(frozen=True)
class DnsAnswer:
    rcode: Rcode
    records: tuple[ResourceRecord, ...] = ()


class Resolver(Protocol):
    async def resolve(self, name: str, rtype: str) -> DnsAnswer:
        """Answer for `name`/`rtype`; raises `DnsError` when there is none."""
        ...


def _name(value: dns.name.Name) -> str:
    return value.to_text(omit_final_dot=True).lower()


def _value(rdata: object, rtype: int) -> str:
    if rtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        return str(rdata.address)  # type: ignore[attr-defined]
    if rtype in (dns.rdatatype.CNAME, dns.rdatatype.NS):
        return _name(rdata.target)  # type: ignore[attr-defined]
    if rtype == dns.rdatatype.MX:
        return "" if rdata.exchange == dns.name.root else _name(rdata.exchange)  # type: ignore[attr-defined]
    if rtype == dns.rdatatype.TXT:
        return b"".join(rdata.strings).decode("utf-8", "replace")  # type: ignore[attr-defined]
    return rdata.to_text()  # type: ignore[attr-defined]


def answer_from_message(message: dns.message.Message) -> DnsAnswer:
    rcode = message.rcode()
    if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        raise DnsError(dns.rcode.to_text(rcode))
    records = tuple(
        ResourceRecord(
            _name(rrset.name), dns.rdatatype.to_text(rrset.rdtype), _value(rd, rrset.rdtype)
        )
        for rrset in message.answer
        for rd in rrset
    )
    return DnsAnswer("NXDOMAIN" if rcode == dns.rcode.NXDOMAIN else "NOERROR", records)


class DnspythonResolver:
    """The real resolver: the OS-configured recursive resolver, through dnspython."""

    def __init__(
        self, resolver: dns.asyncresolver.Resolver | None = None, timeout: float = 5.0
    ) -> None:
        self.timeout = timeout
        self._resolver = resolver  # built lazily: creating one reads the OS configuration

    def _get(self) -> dns.asyncresolver.Resolver:
        if self._resolver is None:
            self._resolver = dns.asyncresolver.Resolver()
            self._resolver.lifetime = self.timeout
        return self._resolver

    async def resolve(self, name: str, rtype: str) -> DnsAnswer:
        try:
            # No search list: `www` must never be completed with the host's own domain.
            answer = await self._get().resolve(name, rtype, raise_on_no_answer=False, search=False)
        except dns.resolver.NXDOMAIN as exc:
            responses = list(exc.responses().values())
            return answer_from_message(responses[0]) if responses else DnsAnswer("NXDOMAIN")
        except dns.exception.DNSException as exc:
            raise DnsError(type(exc).__name__) from None
        return answer_from_message(answer.response)
