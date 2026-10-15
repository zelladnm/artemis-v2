"""Opt-in providers. No provider uploads files or executes samples."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

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


class VirusTotalProvider:
    """Read-only VirusTotal v3 indicator lookup, enabled only by explicit CLI opt-in."""
    name = "virustotal"
    _paths = {"md5": "files", "sha1": "files", "sha256": "files",
              "ipv4": "ip_addresses", "ipv6": "ip_addresses", "domain": "domains"}

    def __init__(self, api_key: str | None = None, timeout: float = 10.0):
        self._api_key = api_key or os.getenv("VT_API_KEY")
        if not self._api_key:
            raise ValueError("VT_API_KEY is required for VirusTotal mode")
        if timeout <= 0 or timeout > 60:
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
                result = json.load(response)
        except HTTPError as exc:
            if exc.code == 404:
                return []
            raise ProviderError(f"VirusTotal lookup failed (HTTP {exc.code})") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ProviderError("VirusTotal network request failed") from exc
        except (ValueError, TypeError) as exc:
            raise ProviderError("VirusTotal returned invalid JSON") from exc

        if not isinstance(result, dict):
            raise ProviderError("VirusTotal response is not an object")
        attributes = result.get("data", {}).get("attributes", {})
        if not isinstance(attributes, dict):
            raise ProviderError("VirusTotal response has no valid attributes")
        counts = attributes.get("last_analysis_stats", {})
        if not isinstance(counts, dict):
            counts = {}
        names = ("malicious", "suspicious", "harmless", "undetected")
        summary = ", ".join(f"{name}: {counts.get(name, 0)}" for name in names)
        ts = attributes.get("last_analysis_date")
        observed = None
        if isinstance(ts, (int, float)):
            try:
                observed = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                pass
        gui_type = {"files": "file", "ip_addresses": "ip-address", "domains": "domain"}[object_type]
        return [Evidence(provider=self.name, category="vendor-detection-counts",
                         summary=summary + ". These counts are not a probability of maliciousness.",
                         reference=f"https://www.virustotal.com/gui/{gui_type}/{encoded}",
                         observed_at=observed)]
