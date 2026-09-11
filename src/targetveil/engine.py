"""TargetVeil sanitization engine."""

from __future__ import annotations

from collections.abc import Iterable

from .detectors import detect_builtin, detect_custom, filter_allowlist
from .models import Finding, Replacement, SanitizeResult


_PROFILE_TYPES: dict[str, set[str] | None] = {
    "balanced": None,
    "burp": None,
    "nmap": {"PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "MAC_ADDRESS", "CUSTOM"},
    "nuclei": {
        "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "AUTH_TOKEN", "COOKIE", "SECRET",
        "JWT", "API_KEY", "USERNAME", "CUSTOM",
    },
    "ffuf": {
        "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "AUTH_TOKEN", "COOKIE", "SECRET",
        "JWT", "API_KEY", "USERNAME", "CUSTOM",
    },
    "bloodhound": {
        "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "USERNAME", "PERSON", "SID", "GUID",
        "LABELED_HOST", "MAC_ADDRESS", "CUSTOM",
    },
    "siem": None,
    "sqlmap": {
        "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "AUTH_TOKEN", "COOKIE", "SECRET",
        "JWT", "API_KEY", "USERNAME", "DATABASE_USER", "CUSTOM",
    },
    "web_discovery": {
        "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "AUTH_TOKEN", "COOKIE", "SECRET",
        "JWT", "API_KEY", "USERNAME", "CUSTOM",
    },
    "netexec": {
        "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "USERNAME", "SECRET", "NTLM_HASH", "SID",
        "GUID", "LABELED_HOST", "MAC_ADDRESS", "CUSTOM",
    },
    "mimikatz": {"DOMAIN", "USERNAME", "SECRET", "NTLM_HASH", "SID", "GUID", "CUSTOM"},
    "metasploit": None,
    "wireshark": {
        "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "MAC_ADDRESS", "EMAIL", "AUTH_TOKEN", "COOKIE",
        "SECRET", "JWT", "API_KEY", "CUSTOM",
    },
    "vuln_scanner": None,
    "cloud": {
        "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "USERNAME", "SECRET", "API_KEY", "JWT",
        "CLOUD_ACCOUNT", "CLOUD_RESOURCE", "AZURE_ID", "K8S_SECRET", "GUID", "CUSTOM",
    },
    "osint": {
        "PUBLIC_IP", "DOMAIN", "EMAIL", "USERNAME", "PHONE", "PERSON", "ADDRESS",
        "PASSPORT_ID", "NATIONAL_ID", "CUSTOM",
    },
    "strict": None,
}


class Sanitizer:
    """Detect and replace sensitive values entirely on the local machine."""

    def scan(
        self,
        text: str,
        *,
        profile: str = "balanced",
        custom_values: Iterable[tuple[str, str]] = (),
        allow_terms: Iterable[str] = (),
    ) -> list[Finding]:
        if profile not in _PROFILE_TYPES:
            raise ValueError(f"unknown profile: {profile}")
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        findings = detect_builtin(text, strict=profile == "strict")
        findings.extend(detect_custom(text, custom_values))
        findings = filter_allowlist(findings, allow_terms)
        enabled = _PROFILE_TYPES[profile]
        if enabled is not None:
            findings = [finding for finding in findings if finding.entity_type in enabled]
        return self._resolve_overlaps(findings)

    def sanitize(
        self,
        text: str,
        *,
        profile: str = "balanced",
        mode: str = "pseudonymize",
        custom_values: Iterable[tuple[str, str]] = (),
        allow_terms: Iterable[str] = (),
        verify: bool = True,
    ) -> SanitizeResult:
        if mode not in {"pseudonymize", "redact"}:
            raise ValueError("mode must be 'pseudonymize' or 'redact'")

        findings = self.scan(
            text,
            profile=profile,
            custom_values=custom_values,
            allow_terms=allow_terms,
        )
        keys_to_placeholders: dict[tuple[str, str], str] = {}
        counters: dict[str, int] = {}
        replacements: list[Replacement] = []

        for finding in findings:
            normalized = finding.normalized if finding.normalized is not None else finding.value
            key = (finding.entity_type, normalized)
            if mode == "redact":
                placeholder = f"{{{{REDACTED_{finding.entity_type}}}}}"
            else:
                placeholder = keys_to_placeholders.get(key, "")
                if not placeholder:
                    counters[finding.entity_type] = counters.get(finding.entity_type, 0) + 1
                    placeholder = (
                        f"{{{{REDACTED_{finding.entity_type}_{counters[finding.entity_type]:03d}}}}}"
                    )
                    while placeholder in text:
                        counters[finding.entity_type] += 1
                        placeholder = (
                            f"{{{{REDACTED_{finding.entity_type}_{counters[finding.entity_type]:03d}}}}}"
                        )
                    keys_to_placeholders[key] = placeholder
            replacements.append(Replacement(finding=finding, placeholder=placeholder))

        output: list[str] = []
        output_replacement_spans: list[tuple[int, int]] = []
        output_length = 0
        cursor = 0
        for replacement in replacements:
            prefix = text[cursor : replacement.finding.start]
            output.append(prefix)
            output_length += len(prefix)
            start = output_length
            output.append(replacement.placeholder)
            output_length += len(replacement.placeholder)
            output_replacement_spans.append((start, output_length))
            cursor = replacement.finding.end
        output.append(text[cursor:])
        sanitized_text = "".join(output)

        residual: list[Finding] = []
        if verify:
            candidates = self.scan(
                sanitized_text,
                profile=profile,
                custom_values=custom_values,
                allow_terms=allow_terms,
            )
            residual = [
                finding
                for finding in candidates
                if not any(
                    finding.start >= start and finding.end <= end
                    for start, end in output_replacement_spans
                )
            ]

        return SanitizeResult(
            original_length=len(text),
            sanitized_text=sanitized_text,
            replacements=replacements,
            residual_findings=residual,
        )

    @staticmethod
    def restore(text: str, replacements: Iterable[Replacement]) -> str:
        """Restore pseudonyms locally. The mapping must never be sent upstream."""

        restored = text
        mappings: dict[str, str] = {}
        for replacement in replacements:
            mappings.setdefault(replacement.placeholder, replacement.finding.value)
        for placeholder, original in sorted(mappings.items(), key=lambda item: len(item[0]), reverse=True):
            restored = restored.replace(placeholder, original)
        return restored

    @staticmethod
    def _resolve_overlaps(findings: Iterable[Finding]) -> list[Finding]:
        candidates = sorted(
            findings,
            key=lambda item: (-item.priority, -item.confidence, -item.length, item.start),
        )
        selected: list[Finding] = []
        for candidate in candidates:
            if any(candidate.start < item.end and item.start < candidate.end for item in selected):
                continue
            selected.append(candidate)
        return sorted(selected, key=lambda item: (item.start, item.end))
