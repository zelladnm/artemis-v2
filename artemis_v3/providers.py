"""Opt-in providers. No provider uploads files or executes samples."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import math
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, HTTPRedirectHandler, build_opener

from .indicators import Indicator, is_external_lookup_safe
from .models import Evidence


class ProviderError(Exception):
    """A provider failed. Safe to show without disclosing credentials."""


class Provider(Protocol):
    name: str

    def lookup(self, indicator: Indicator) -> list[Evidence]: ...


class DemoProvider:
    """Deterministic, synthetic offline fixtures; never make network calls."""
    name = "demo"
    _fixtures = {
        "demo.example": "Synthetic indicator referenced by a simulated security alert.",
        "203.0.113.10": "Synthetic network address from the RFC 5737 documentation range.",
        "a" * 64: "Synthetic hash representing an illustrative file investigation.",
    }

    def lookup(self, indicator: Indicator) -> list[Evidence]:
        summary = self._fixtures.get(indicator.value)
        if summary is None:
            return []
        return [Evidence(provider=self.name, category="simulated-observation",
                         summary=summary, reference="demo://artemis-v3/fixtures",
                         synthetic=True)]


MAX_VT_RESPONSE_BYTES = 2 * 1024 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a credential-bearing request to a redirected location.
        return None


# Preserve a single patchable transport boundary for offline contract tests.
urlopen = build_opener(_NoRedirect).open


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Non-finite JSON number")


class VirusTotalProvider:
    """Read-only VirusTotal v3 indicator lookup, enabled only by explicit CLI opt-in."""
    name = "virustotal"
    _paths = {"md5": "files", "sha1": "files", "sha256": "files",
              "ipv4": "ip_addresses", "ipv6": "ip_addresses", "domain": "domains"}

    def __init__(self, api_key: str | None = None, timeout: float = 10.0):
        self._api_key = api_key or os.getenv("VT_API_KEY")
        if not self._api_key:
            raise ValueError("VT_API_KEY is required for VirusTotal mode")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("Timeout must be between 0 and 60 seconds")
        self._timeout = timeout

    def lookup(self, indicator: Indicator) -> list[Evidence]:
        if not is_external_lookup_safe(indicator):
            raise ProviderError("External query blocked for private/reserved or local indicator")
        object_type = self._paths[indicator.kind]
        encoded = quote(indicator.value, safe="")
        url = f"https://www.virustotal.com/api/v3/{object_type}/{encoded}"
        request = Request(url, headers={"x-apikey": self._api_key, "Accept": "application/json"})
        try:
            with urlopen(request, timeout=self._timeout) as response:
                raw = response.read(MAX_VT_RESPONSE_BYTES + 1)
                if len(raw) > MAX_VT_RESPONSE_BYTES:
                    raise ProviderError("VirusTotal response exceeds the 2 MiB limit")
                result = json.loads(raw, object_pairs_hook=_json_pairs, parse_constant=_reject_constant)
        except HTTPError as exc:
            if exc.code == 404:
                return []
            raise ProviderError(f"VirusTotal lookup failed (HTTP {exc.code})") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ProviderError("VirusTotal network request failed") from exc
        except (ValueError, TypeError, RecursionError) as exc:
            raise ProviderError("VirusTotal returned invalid JSON") from exc

        if not isinstance(result, dict) or not isinstance(result.get("data"), dict):
            raise ProviderError("VirusTotal response has no valid data object")
        data = result["data"]
        expected_type = {"files": "file", "ip_addresses": "ip_address", "domains": "domain"}[object_type]
        attributes = data.get("attributes")
        if data.get("type") != expected_type or not isinstance(attributes, dict):
            raise ProviderError("VirusTotal response has invalid object type or attributes")
        identity = attributes.get(indicator.kind) if indicator.kind in {"md5", "sha1"} else data.get("id")
        if not isinstance(identity, str) or identity.lower() != indicator.value.lower():
            raise ProviderError("VirusTotal response identity does not match the requested indicator")
        counts = attributes.get("last_analysis_stats")
        names = ("malicious", "suspicious", "harmless", "undetected")
        if (not isinstance(counts, dict) or not any(name in counts for name in names) or
                any(type(count) is not int or count < 0 for count in counts.values())):
            raise ProviderError("VirusTotal detection counts are unavailable or invalid")
        summary = ", ".join(f"{name}: {counts[name] if name in counts else 'unknown'}" for name in names)
        observed = None
        if "last_analysis_date" in attributes:
            ts = attributes["last_analysis_date"]
            if type(ts) is not int or not 0 <= ts <= 253402300799:
                raise ProviderError("VirusTotal analysis timestamp is invalid")
            try:
                observed = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError) as exc:
                raise ProviderError("VirusTotal analysis timestamp is out of range") from exc
        gui_type = {"files": "file", "ip_addresses": "ip-address", "domains": "domain"}[object_type]
        return [Evidence(provider=self.name, category="vendor-detection-counts",
                         summary=summary + ". These counts are not a probability of maliciousness.",
                         reference=f"https://www.virustotal.com/gui/{gui_type}/{encoded}",
                         observed_at=observed)]
