# TargetVeil product roadmap

This document separates shipped capabilities from future work. It prevents the project from presenting a proof of concept as a complete data-loss-prevention product.

## Shipped in v0.2

- Static browser application with no prompt backend, telemetry or browser storage.
- Seventeen pentest-first profiles covering web, network, AD, exploitation, vulnerability scanning, cloud, OSINT and logs.
- A runnable synthetic example with declared leakage canaries for every profile.
- Explainable detections with rule name, confidence, reason and deterministic replacement.
- Relationship-preserving domain, email and IPv4 pseudonyms.
- Local evidence-file import and sanitized-file download.
- Per-engagement scope files and explicit allowlists.
- Global core detection and initial regional identifier packs.
- Browser and Python CLI engines with automated regression tests.

## Useful capabilities found in neighboring tools

These are meaningful gaps, not defects hidden behind marketing language:

| Capability | Seen in | TargetVeil v0.2 |
| --- | --- | --- |
| NLP/NER for unlabelled people, organizations and addresses | [Microsoft Presidio](https://microsoft.github.io/presidio/) | Not included; labelled fields and deterministic patterns only |
| Structured table/dataframe and image redaction | [Microsoft Presidio](https://microsoft.github.io/presidio/) | Text-based exports only |
| Large secret-rule corpus, entropy checks and recursive decoding | [Gitleaks](https://github.com/gitleaks/gitleaks) | Curated high-confidence secret patterns only |
| Transparent AI API proxy and streaming interception | [DontFeedTheAI](https://github.com/zeroc00I/DontFeedTheAI) | Not included in the hosted static app |
| Automatic restoration of pseudonyms in an AI response | Proxy-based tools | Not included; avoids handling AI traffic |
| OCR, PDF and Office-document ingestion | DLP suites / Presidio extensions | Not included |
| Browser extension, Burp extension and editor integrations | Various ecosystem tools | Not included |
| Encrypted persistent engagement vault | Proxy/local-agent tools | Intentionally absent from the web app |

## Next milestones

### v0.3 — deeper detection

- Pluggable secret-rule packs with per-rule tests and provenance.
- Safe decoding preview for URL encoding, Base64 and nested JSON, with hard depth and size limits.
- More regional identifiers with official validation rules.
- Configurable confidence threshold and false-positive feedback export that stays local.
- Parser-aware HAR, Nessus, Nmap XML and JSON Lines processing.

### v0.4 — professional integrations

- Optional Burp Suite extension that calls the same local engine.
- Browser extension with an explicit preview gate before copying into AI sites.
- SARIF/JSON audit report containing positions and categories but never original values.
- Signed release artifacts and reproducible static builds.

### v1.0 — release quality

- Versioned detector contract and backward-compatible scope schema.
- Cross-browser end-to-end coverage for Chromium, Firefox and WebKit.
- Accessibility audit against WCAG 2.2 AA.
- Fuzz/property tests and public synthetic benchmark corpus.
- Independent security review and published results.

## Non-goals for the GitHub Pages build

- Sending prompts directly to an AI provider.
- Server-side accounts, analytics, synchronization or storage.
- Claiming that automated sanitization guarantees compliance or complete detection.
- Replacing an engagement's legal, contractual or client data-handling requirements.

