"""Typed evidence objects; model conclusions never overwrite source observations."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .indicators import Indicator


@dataclass(frozen=True)
class Evidence:
    provider: str
    category: str
    summary: str
    reference: str
    observed_at: str | None = None
    synthetic: bool = False


@dataclass
class Investigation:
    indicator: Indicator
    status: str
    evidence: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)

    def as_markdown(self) -> str:
        lines = ["# Artemis v3 — IOC Investigation", "",
                 f"**Indicator:** {self.indicator.value} ({self.indicator.kind})",
                 f"**Status:** {self.status}", ""]
        if any(item.synthetic for item in self.evidence):
            lines += ["> **DEMO DATA:** Synthetic fixtures, not real threat intelligence.", ""]
        if not self.evidence:
            lines += ["No evidence was returned. **Absence of evidence does not mean benign.**", ""]
        else:
            lines += ["## Evidence", ""]
            for item in self.evidence:
                summary = item.summary.replace("\n", " ").replace(chr(96), "'")
                lines += [f"- **{item.provider} / {item.category}:** {summary}",
                          f"  - Source: {item.reference}",
                          f"  - Observed: {item.observed_at or 'unknown'}"]
            lines += [""]
        if self.errors:
            lines += ["## Provider warnings", ""]
            lines += [f"- {error}" for error in self.errors]
            lines += [""]
        lines += ["## Interpretation", "",
                  "These are source observations, not a malware verdict. Validate findings against endpoint and network evidence."]
        return "\n".join(lines) + "\n"
