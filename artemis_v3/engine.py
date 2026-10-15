"""Stateless investigation orchestration (one investigation per invocation)."""
from __future__ import annotations

from collections.abc import Iterable

from .indicators import parse_indicator
from .models import Investigation
from .providers import Provider, ProviderError


def investigate(raw_indicator: str, providers: Iterable[Provider]) -> Investigation:
    indicator = parse_indicator(raw_indicator)
    evidence = []
    errors = []
    for provider in providers:
        try:
            evidence.extend(provider.lookup(indicator))
        except ProviderError as exc:
            errors.append(f"{provider.name}: {exc}")
    status = ("partial" if errors else "completed") if evidence else ("failed" if errors else "no_evidence")
    return Investigation(indicator=indicator, evidence=evidence, errors=errors, status=status)
