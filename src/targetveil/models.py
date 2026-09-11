"""Core data models used by detectors and sanitizers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Finding:
    """A sensitive span in the original input."""

    entity_type: str
    start: int
    end: int
    value: str
    detector: str
    confidence: float = 1.0
    priority: int = 50
    normalized: str | None = None

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True, slots=True)
class Replacement:
    """A selected finding and its safe replacement."""

    finding: Finding
    placeholder: str


@dataclass(slots=True)
class SanitizeResult:
    """Output returned after a sanitization pass."""

    original_length: int
    sanitized_text: str
    replacements: list[Replacement] = field(default_factory=list)
    residual_findings: list[Finding] = field(default_factory=list)

    @property
    def safe(self) -> bool:
        return not self.residual_findings

    @property
    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for replacement in self.replacements:
            kind = replacement.finding.entity_type
            counts[kind] = counts.get(kind, 0) + 1
        return dict(sorted(counts.items()))

