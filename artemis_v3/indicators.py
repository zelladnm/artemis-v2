"""Parse indicators without sending data to a third-party service."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HASH_RE = re.compile(r"[0-9a-fA-F]+\Z", re.ASCII)
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str


def parse_indicator(raw: str) -> Indicator:
    """Return normalized hash, IPv4/IPv6, or DNS name; reject URLs and paths."""
    if not isinstance(raw, str):
        raise ValueError("Indicator must be a string")
    value = raw.strip()
    if not value or len(value) > 253 or any(ch.isspace() for ch in value):
        raise ValueError("Indicator is empty, too long, or contains whitespace")

    if len(value) in _HASH_LENGTHS and _HASH_RE.fullmatch(value):
        return Indicator(_HASH_LENGTHS[len(value)], value.lower())

    try:
        address = ipaddress.ip_address(value)
        return Indicator("ipv4" if address.version == 4 else "ipv6", address.compressed)
    except ValueError:
        pass

    if ":" in value or "/" in value or "@" in value or "\\" in value:
        raise ValueError("Unsupported indicator: provide a hash, IP address, or domain")

    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid domain encoding") from exc
    labels = domain.split(".")
    if (len(domain) > 253 or len(labels) < 2 or
            any(not _LABEL_RE.fullmatch(label) for label in labels) or
            (not labels[-1].startswith("xn--") and not labels[-1].isalpha())):
        raise ValueError("Unsupported or invalid domain name")
    if all(label.isdigit() for label in labels):
        raise ValueError("Invalid IP address")
    return Indicator("domain", domain)


def is_external_lookup_safe(indicator: Indicator) -> bool:
    """Coarse guard against sharing private/reserved network indicators."""
    if indicator.kind in {"ipv4", "ipv6"}:
        return ipaddress.ip_address(indicator.value).is_global
    if indicator.kind == "domain":
        blocked = (".local", ".internal", ".localhost", ".test", ".example", ".invalid")
        return indicator.value not in {"localhost", "example.com", "example.net", "example.org"} and not indicator.value.endswith(blocked)
    return True
