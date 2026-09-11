"""Offline detectors focused on common pentest and assessment data."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from .models import Finding


_EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}(?![\w.-])", re.I)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.I)
_MAC = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])", re.I)
_DOMAIN = re.compile(
    r"(?<![\w@])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|local|internal|lan|corp)(?![\w.-])",
    re.I,
)
_JWT = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])")
_API_KEY = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9]{20,255}|"
    r"github_pat_[A-Za-z0-9_]{20,255}|"
    r"glpat-[A-Za-z0-9_-]{20,255}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,255}|"
    r"(?:sk|rk)_live_[A-Za-z0-9]{16,255}|"
    r"AIza[0-9A-Za-z_-]{35}|"
    r"SK[0-9a-fA-F]{32}|"
    r"sk-[A-Za-z0-9_-]{20,255}"
    r")(?![A-Za-z0-9])"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.S,
)
_AUTH = re.compile(
    r"(?im)^[ \t]*authorization[ \t]*:[ \t]*(?:bearer|basic|digest)[ \t]+([^\s\r\n]+)"
)
_COOKIE = re.compile(r"(?im)^[ \t]*(?:set-)?cookie[ \t]*:[ \t]*([^\s\r\n][^\r\n]*)")
_SENSITIVE_FIELD = re.compile(
    r"(?i)(?:password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|session[_-]?id|aws[_-]?secret[_-]?access[_-]?key)"
    r"[\"']?[ \t]*[=:][ \t]*[\"']?([^&\s\"',;}{]+)"
)
_USERNAME_FIELD = re.compile(
    r"(?i)(?:user(?:name)?|login|account)[\"']?[ \t]*[=:][ \t]*[\"']?([^&\s\"',;}{]+)"
)
_PHONE = re.compile(r"(?<!\d)(?:\+?30[ .-]?)?(?:2\d{9}|69\d{8})(?!\d)")
_GENERIC_PHONE = re.compile(r"(?<!\d)\+\d{1,3}[ .-]?(?:\(?\d{2,4}\)?[ .-]?){2,4}\d{2,4}(?!\d)")
_CREDIT_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_GREEK_AFM_CONTEXT = re.compile(r"(?i)(?:ΑΦΜ|AFM|VAT(?:\s+number)?)\s*[:=]?\s*(\d{9})(?!\d)")
_GREEK_AMKA_CONTEXT = re.compile(r"(?i)(?:ΑΜΚΑ|AMKA)\s*[:=]?\s*(\d{11})(?!\d)")
_IBAN = re.compile(r"(?<![A-Z0-9])([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30})(?![A-Z0-9])", re.I)
_EU_VAT_CONTEXT = re.compile(
    r"(?i)(?:EU\s+VAT|VAT\s+ID|VAT\s+number|ΑΦΜ)\s*[:=]?\s*([A-Z]{2}[A-Z0-9]{8,12})(?![A-Z0-9])"
)
_LABELED_PERSON = re.compile(
    r"(?im)^\s*(?:full\s+name|first\s+name|last\s+name|contact|όνομα|επώνυμο|ονοματεπώνυμο)"
    r"\s*[:=]\s*([^\r\n,;]{2,100})"
)
_LABELED_ADDRESS = re.compile(
    r"(?im)^\s*(?:address|home\s+address|διεύθυνση|διευθυνση)\s*[:=]\s*([^\r\n]{5,200})"
)
_SID = re.compile(r"(?<![\w-])S-1-5-21-(?:\d+-){2}\d+(?:-\d+)?(?![\w-])", re.I)
_GUID = re.compile(
    r"(?<![A-F0-9])[A-F0-9]{8}-[A-F0-9]{4}-[1-5][A-F0-9]{3}-"
    r"[89AB][A-F0-9]{3}-[A-F0-9]{12}(?![A-F0-9])",
    re.I,
)
_LABELED_HOST = re.compile(
    r"(?i)(?:host|hostname|computer|workstation)[\"']?[ \t]*[=:][ \t]*[\"']?([A-Z0-9_-]{2,63})"
)
_AD_PRINCIPAL = re.compile(r"(?<![\w])(?:[A-Z0-9._-]+\\[A-Z0-9.$_-]+)(?![\w])", re.I)
_HOME_PATH_USER = re.compile(r"(?:[A-Z]:\\Users\\|/home/)([^\\/\s]+)", re.I)
_CREDENTIAL_DUMP_USER = re.compile(
    r"(?im)(?:user(?:[ \t_-]*name)?|login)[ \t]*:[ \t]*([^\s*][^\r\n]{0,63}?)(?=[ \t]*$)"
)
_NTLM_HASH = re.compile(r"(?i)(?:NTLM|NT[ \t]+hash|nthash)[ \t]*:[ \t]*([a-f0-9]{32})(?![a-f0-9])")
_DATABASE_URI_USER = re.compile(
    r"(?i)(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql)://([^:\s/@]+):(?=[^@\s]+@)"
)
_DATABASE_URI_PASSWORD = re.compile(
    r"(?i)(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql)://[^:\s/@]+:([^@\s]+)@"
)
_CONNECTION_USER = re.compile(r"(?i)(?:User[ \t]+Id|UID)[ \t]*=[ \t]*([^;\r\n]+)")
_CONNECTION_PASSWORD = re.compile(r"(?i)(?:Password|PWD)[ \t]*=[ \t]*([^;\r\n]+)")
_AWS_ACCOUNT = re.compile(
    r"(?i)(?:AWS[ \t_-]*account(?:[ \t_-]*id)?|accountId)[\"']?[ \t]*[=:][ \t]*[\"']?(\d{12})(?!\d)"
)
_AWS_ARN = re.compile(
    r"(?<![A-Za-z0-9])arn:(?:aws|aws-us-gov|aws-cn):[A-Za-z0-9-]*:[A-Za-z0-9-]*:\d{12}:[^\s\"']+"
)
_AZURE_ID = re.compile(
    r"(?i)(?:tenant(?:[ \t_-]*id)?|subscription(?:[ \t_-]*id)?|object(?:[ \t_-]*id)?)"
    r"[\"']?[ \t]*[=:][ \t]*[\"']?([A-F0-9]{8}-[A-F0-9]{4}-[1-5][A-F0-9]{3}-"
    r"[89AB][A-F0-9]{3}-[A-F0-9]{12})"
)
_GCP_PROJECT = re.compile(
    r"(?i)(?:project(?:[ \t_-]*id)?|gcp[ \t_-]*project)[\"']?[ \t]*[=:][ \t]*[\"']?"
    r"([a-z][a-z0-9-]{5,29})(?![a-z0-9-])"
)
_KUBECONFIG_SECRET = re.compile(
    r"(?im)^[ \t]*(?:token|client-key-data|client-certificate-data)[ \t]*:[ \t]*([^\s#][^\r\n#]*)"
)

_FILELIKE_SUFFIXES = {
    "bash", "conf", "config", "css", "csv", "env", "go", "gz", "html", "ini", "java",
    "jpeg", "jpg", "js", "json", "log", "md", "pem", "php", "png", "ps1", "py", "rb",
    "sh", "sql", "svg", "tar", "toml", "ts", "txt", "xml", "yaml", "yml", "zip",
}
_SAFE_DOMAINS = {
    "example.com", "example.net", "example.org", "localhost",
}


def _finding(
    entity_type: str,
    match: re.Match[str],
    detector: str,
    *,
    group: int = 0,
    confidence: float = 1.0,
    priority: int = 50,
    normalized: str | None = None,
) -> Finding:
    value = match.group(group)
    return Finding(
        entity_type=entity_type,
        start=match.start(group),
        end=match.end(group),
        value=value,
        detector=detector,
        confidence=confidence,
        priority=priority,
        normalized=normalized,
    )


def _luhn_valid(candidate: str) -> bool:
    digits = [int(char) for char in candidate if char.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _afm_valid(value: str) -> bool:
    if len(value) != 9 or not value.isdigit() or len(set(value)) == 1:
        return False
    total = sum(int(value[index]) * (2 ** (8 - index)) for index in range(8))
    return total % 11 % 10 == int(value[-1])


def _iban_valid(value: str) -> bool:
    compact = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for character in rearranged:
        expanded = str(ord(character) - 55) if character.isalpha() else character
        for digit in expanded:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


def detect_builtin(text: str, *, strict: bool = False) -> list[Finding]:
    """Return high-confidence built-in findings without making network calls."""

    findings: list[Finding] = []

    for match in _PRIVATE_KEY.finditer(text):
        findings.append(_finding("PRIVATE_KEY", match, "private-key", priority=100))
    for match in _AUTH.finditer(text):
        findings.append(_finding("AUTH_TOKEN", match, "authorization-header", group=1, priority=95))
    for match in _COOKIE.finditer(text):
        findings.append(_finding("COOKIE", match, "cookie-header", group=1, priority=94))
    for match in _SENSITIVE_FIELD.finditer(text):
        findings.append(_finding("SECRET", match, "sensitive-field", group=1, priority=92))
    for match in _JWT.finditer(text):
        findings.append(_finding("JWT", match, "jwt", priority=91))
    for match in _API_KEY.finditer(text):
        findings.append(_finding("API_KEY", match, "api-key", priority=90))

    for match in _DATABASE_URI_USER.finditer(text):
        findings.append(
            _finding(
                "DATABASE_USER", match, "database-uri-user", group=1, priority=88,
                normalized=match.group(1).lower(),
            )
        )
    for match in _DATABASE_URI_PASSWORD.finditer(text):
        findings.append(_finding("SECRET", match, "database-uri-password", group=1, priority=97))
    for match in _CONNECTION_USER.finditer(text):
        findings.append(
            _finding(
                "DATABASE_USER", match, "connection-string-user", group=1, priority=87,
                normalized=match.group(1).strip().lower(),
            )
        )
    for match in _CONNECTION_PASSWORD.finditer(text):
        findings.append(_finding("SECRET", match, "connection-string-password", group=1, priority=97))
    for match in _NTLM_HASH.finditer(text):
        findings.append(
            _finding(
                "NTLM_HASH", match, "ntlm-hash-context", group=1, priority=96,
                normalized=match.group(1).lower(),
            )
        )
    for match in _AWS_ACCOUNT.finditer(text):
        findings.append(_finding("CLOUD_ACCOUNT", match, "aws-account-context", group=1, priority=86))
    for match in _AWS_ARN.finditer(text):
        findings.append(_finding("CLOUD_RESOURCE", match, "aws-arn", priority=89))
    for match in _AZURE_ID.finditer(text):
        findings.append(
            _finding(
                "AZURE_ID", match, "azure-id-context", group=1, priority=90,
                normalized=match.group(1).lower(),
            )
        )
    for match in _GCP_PROJECT.finditer(text):
        findings.append(
            _finding(
                "CLOUD_RESOURCE", match, "gcp-project-context", group=1, priority=85,
                normalized=match.group(1).lower(),
            )
        )
    for match in _KUBECONFIG_SECRET.finditer(text):
        findings.append(
            _finding(
                "K8S_SECRET", match, "kubeconfig-secret", group=1, priority=98,
                normalized=match.group(1).strip(),
            )
        )

    for match in _EMAIL.finditer(text):
        findings.append(
            _finding("EMAIL", match, "email", priority=80, normalized=match.group(0).casefold())
        )

    for match in _IPV4.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if address.is_loopback or address.is_unspecified:
            if not strict:
                continue
        kind = "PRIVATE_IP" if address.is_private else "PUBLIC_IP"
        findings.append(_finding(kind, match, "ipv4", priority=75, normalized=address.compressed))

    for match in _IPV6.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if address.is_loopback or address.is_unspecified:
            if not strict:
                continue
        kind = "PRIVATE_IP" if address.is_private else "PUBLIC_IP"
        findings.append(_finding(kind, match, "ipv6", priority=75, normalized=address.compressed))

    for match in _MAC.finditer(text):
        findings.append(_finding("MAC_ADDRESS", match, "mac", priority=75, normalized=match.group(0).lower()))

    for match in _DOMAIN.finditer(text):
        value = match.group(0).rstrip(".")
        normalized = value.casefold()
        suffix = normalized.rsplit(".", 1)[-1]
        if normalized in _SAFE_DOMAINS or normalized.endswith(".example"):
            continue
        if suffix in _FILELIKE_SUFFIXES:
            continue
        findings.append(_finding("DOMAIN", match, "domain", priority=70, normalized=normalized))

    for match in _USERNAME_FIELD.finditer(text):
        value = match.group(1)
        if value.lower() not in {"admin", "administrator", "root", "guest", "test"} or strict:
            findings.append(_finding("USERNAME", match, "username-field", group=1, priority=78))
    for match in _HOME_PATH_USER.finditer(text):
        findings.append(
            _finding(
                "USERNAME", match, "home-path-user", group=1, priority=76,
                normalized=match.group(1).lower(),
            )
        )
    for match in _CREDENTIAL_DUMP_USER.finditer(text):
        value = match.group(1).strip()
        if value.lower() not in {"null", "none", "(null)"} or strict:
            findings.append(
                _finding(
                    "USERNAME", match, "credential-dump-user", group=1, priority=83,
                    normalized=value.lower(),
                )
            )

    for match in _PHONE.finditer(text):
        findings.append(_finding("PHONE", match, "greek-phone", priority=65))
    for match in _GENERIC_PHONE.finditer(text):
        findings.append(_finding("PHONE", match, "international-phone", priority=64))
    for match in _CREDIT_CARD.finditer(text):
        if _luhn_valid(match.group(0)):
            findings.append(_finding("CREDIT_CARD", match, "credit-card-luhn", priority=85))

    for match in _GREEK_AFM_CONTEXT.finditer(text):
        if _afm_valid(match.group(1)):
            findings.append(_finding("GREEK_AFM", match, "greek-afm", group=1, priority=85))
    for match in _GREEK_AMKA_CONTEXT.finditer(text):
        findings.append(_finding("GREEK_AMKA", match, "greek-amka", group=1, priority=85))
    for match in _IBAN.finditer(text):
        if _iban_valid(match.group(1)):
            findings.append(
                _finding(
                    "IBAN",
                    match,
                    "iban-mod97",
                    group=1,
                    priority=86,
                    normalized=re.sub(r"\s", "", match.group(1)).upper(),
                )
            )
    for match in _EU_VAT_CONTEXT.finditer(text):
        findings.append(
            _finding(
                "EU_VAT",
                match,
                "eu-vat-context",
                group=1,
                priority=82,
                normalized=match.group(1).upper(),
            )
        )
    for match in _LABELED_PERSON.finditer(text):
        findings.append(_finding("PERSON", match, "labeled-person", group=1, confidence=0.9, priority=60))
    for match in _LABELED_ADDRESS.finditer(text):
        findings.append(_finding("ADDRESS", match, "labeled-address", group=1, confidence=0.9, priority=60))
    for match in _SID.finditer(text):
        findings.append(_finding("SID", match, "windows-sid", priority=82))
    for match in _GUID.finditer(text):
        findings.append(
            _finding("GUID", match, "guid", priority=68, normalized=match.group(0).lower())
        )
    for match in _LABELED_HOST.finditer(text):
        findings.append(
            _finding(
                "LABELED_HOST",
                match,
                "labeled-host",
                group=1,
                priority=67,
                normalized=match.group(1).lower(),
            )
        )
    for match in _AD_PRINCIPAL.finditer(text):
        findings.append(
            _finding(
                "USERNAME",
                match,
                "ad-principal",
                priority=79,
                normalized=match.group(0).lower(),
            )
        )

    return findings


def detect_custom(text: str, values: Iterable[tuple[str, str]]) -> list[Finding]:
    """Detect exact engagement-specific values with case-insensitive matching."""

    findings: list[Finding] = []
    for raw_kind, raw_value in values:
        kind = re.sub(r"[^A-Z0-9_]+", "_", raw_kind.upper()).strip("_") or "CUSTOM"
        value = raw_value.strip()
        if len(value) < 2:
            continue
        pattern = re.compile(re.escape(value), re.I)
        for match in pattern.finditer(text):
            findings.append(
                _finding(kind, match, "custom-exact", priority=99, normalized=value.casefold())
            )
    return findings


def filter_allowlist(findings: Iterable[Finding], allow_terms: Iterable[str]) -> list[Finding]:
    allowed = {term.strip().casefold() for term in allow_terms if term.strip()}
    return [finding for finding in findings if finding.value.casefold() not in allowed]
