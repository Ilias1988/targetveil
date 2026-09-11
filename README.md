# TargetVeil

**Local-first redaction and pseudonymization for AI-assisted penetration testing.**

TargetVeil helps authorized security professionals remove personal data, client infrastructure, credentials and engagement identifiers before sharing technical evidence with a public AI service. The web application performs all detection and replacement inside the browser and has no prompt-processing backend. The hosted pages use Cloudflare Web Analytics; prompts and evidence are not submitted to it by the sanitizer.

Live application: **https://ilias1988.github.io/targetveil/**

> [!IMPORTANT]
> Automated detection cannot guarantee that every sensitive value is found. Always review the sanitized output and follow the engagement's data-handling rules. If third-party AI is prohibited, TargetVeil does not change that restriction.

## Why TargetVeil?

Generic PII scrubbers do not understand the structure of pentest evidence. TargetVeil is designed around HTTP traffic, scanner output, directory-service data and security logs. It keeps ports, methods, paths, status codes and tool evidence useful while replacing target-specific values.

```text
Pentest evidence
      │
      ▼
Local detectors ──► Engagement scope ──► Overlap resolution
      │                                      │
      ▼                                      ▼
Explainable preview ◄── Verification ◄── Pseudonymization
      │
      ▼
Copy sanitized prompt to the AI chosen by the pentester
```

## Features

- Pentest-first profiles for web testing, network discovery, AD, exploitation, vulnerability scanning, cloud, OSINT and SIEM workflows.
- Universal detectors for emails, international phone numbers, IPs, domains, hostnames, MAC addresses, cookies, JWTs, API keys, private keys, credentials, usernames and payment cards.
- Regional identifier packs for the EU/EEA, Greece, United States, United Kingdom, Canada, Australia, India and Brazil.
- Checksum validation where applicable, including Luhn, IBAN mod-97, Greek AFM, Australian TFN, Aadhaar Verhoeff and Brazilian CPF.
- Deterministic pseudonyms that preserve repeated-value, domain-hierarchy and network-range relationships.
- Explainable findings showing what was detected, how it was replaced and why.
- Per-engagement JSON scope files with sensitive values and an allowlist.
- A second detection pass after replacement plus synthetic leakage-canary tests.
- A browser-only application with a restrictive Content Security Policy and no data persistence.
- Local import for text, log, JSON, XML, CSV, HAR, Nessus and Nmap exports up to 10 MB, plus local sanitized-file download.
- A selectable synthetic example for every profile, so visitors can test the complete workflow without real target data.
- A dependency-free Python CLI for disconnected environments and automation.
- Offline-ready static assets through a service worker; prompts are never cached.

## Web application

The production website is made of plain static HTML, CSS and JavaScript in [`docs/`](docs/). GitHub Pages only delivers those public files. Sanitization happens in browser memory.

Run it locally:

```bash
python -m http.server 4173 --directory docs --bind 127.0.0.1
```

Then visit `http://127.0.0.1:4173/`.

For higher-assurance use, clone the repository, disconnect the network, start the local server and review the source before processing engagement material.

### Browser privacy properties

- CSP permits connections only to Cloudflare Web Analytics; the sanitizer engine and UI have no network API.
- No `fetch`, `XMLHttpRequest`, WebSocket or beacon call exists in the application engine/UI.
- No remote fonts or application dependencies. The only third-party script on hosted HTML pages is the disclosed Cloudflare Web Analytics beacon.
- No prompt values are written to cookies, `localStorage`, `sessionStorage` or IndexedDB.
- The service worker caches only static public application assets.
- Reloading or using **Clear page memory** discards the active prompt and mapping.

Evidence-file import uses the browser's local file API. The original file is read into the current tab only; TargetVeil does not upload it. Sanitized downloads are created locally with an in-memory Blob.

GitHub Pages and Cloudflare Web Analytics can receive ordinary website-request and performance metadata. TargetVeil defines no custom analytics events and its sanitizer does not pass prompt fields, evidence, scope data, findings or output to the beacon. Cloudflare's remote script is nevertheless a third-party trust dependency. For higher-assurance work, use the disconnected local or CLI workflow. See the [privacy page](docs/privacy.html) and [threat model](docs/THREAT_MODEL.md).

## CLI

Install the package in an isolated environment:

```bash
python -m venv .venv
python -m pip install -e .
```

Sanitize a file or stdin:

```bash
targetveil sanitize burp-request.txt --profile burp
cat nmap-output.txt | targetveil sanitize --profile nmap
targetveil sanitize evidence.txt --profile strict --mode redact
```

Inspect findings without printing original values:

```bash
targetveil scan evidence.txt --profile siem
```

Add `--show-values` only when local terminal output is safe.

## Engagement scope files

Scope files are read locally and never uploaded. A minimal `.targetveil.json` file looks like this:

```json
{
  "engagement": "Authorized Web Assessment",
  "profile": "burp",
  "region": "global",
  "sensitive_values": [
    { "type": "CLIENT", "value": "Example Client Ltd" },
    { "type": "CLIENT_CODE", "value": "ENG-2026-001" },
    { "type": "DOMAIN", "value": "internal.example-client.test" }
  ],
  "allowlist": ["example.com", "127.0.0.1"]
}
```

Use only synthetic data in committed examples. See [`examples/synthetic-engagement.targetveil.json`](examples/synthetic-engagement.targetveil.json).

## Profiles

| Profile | Intended input |
| --- | --- |
| `balanced` | Mixed assessment notes with lower false-positive noise |
| `burp` | Raw HTTP requests/responses and Burp exports |
| `nmap` | Hosts, addresses and network scan output |
| `nuclei` | Nuclei results, target URLs and authentication material |
| `ffuf` | ffuf output, web targets and request headers |
| `bloodhound` | AD principals, SIDs, GUIDs, domains and computers |
| `siem` | SIEM, EDR and incident-response logs |
| `sqlmap` | SQL injection output, database URIs and connection strings |
| `web_discovery` | Gobuster, Dirsearch, Nikto and WPScan output |
| `netexec` | NetExec, CrackMapExec and Impacket output |
| `mimikatz` | Mimikatz and Secretsdump credential material |
| `metasploit` | Metasploit console, session and loot output |
| `wireshark` | Wireshark and tcpdump text exports |
| `vuln_scanner` | Nessus and OpenVAS exports |
| `cloud` | AWS, Azure, GCP and Kubernetes evidence |
| `osint` | OSINT and reconnaissance notes |
| `strict` | Every available detector, including test-like values |

## Testing

No external services or real target data are used by the test suite.

```bash
npm test
python -m unittest discover -s tests -p "test_*.py" -v
node scripts/verify-static.mjs
```

Tests cover every built-in demo, synthetic canary leakage, HTTP forms and JSON credentials, database URIs, AD hashes, cloud identifiers, compressed IPv6, repeat consistency, network/domain relationships, regional identifiers, custom scopes, local evidence-file validation, false-positive guards, a one-megabyte performance corpus and the static site's privacy invariants.

## Product scope and roadmap

TargetVeil's differentiator is a transparent, dependency-free, pentest-aware browser sanitizer. Mature neighboring projects cover additional use cases: Microsoft Presidio supports configurable recognizers, NLP/NER, structured data and image redaction; Gitleaks has a much larger secret-scanning ruleset with entropy and decoding features; proxy-style projects can intercept AI API traffic and restore pseudonyms in responses.

Those capabilities are not silently claimed here. Planned work and explicit non-goals are tracked in [`PRODUCT_ROADMAP.md`](PRODUCT_ROADMAP.md). The current release intentionally keeps the hosted application static, auditable and unable to transmit prompts.

## Security model and limitations

TargetVeil is designed to reduce accidental disclosure; it is not a compliance guarantee or a replacement for professional review.

It does not protect against:

- a compromised device, browser or malicious browser extension;
- sensitive meaning that no detector or scope value identifies;
- screenshots, clipboard history or other software outside the page;
- a maliciously modified hosted build or compromised GitHub account;
- correlation attacks against insufficiently transformed context;
- client rules that prohibit any third-party AI processing.

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and report vulnerabilities according to [`SECURITY.md`](SECURITY.md).

## Contributing

Contributions for new country packs, pentest formats, validators, test corpora and false-positive reductions are welcome. All fixtures must be synthetic. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Creator

Created by **Ilias Georgopoulos**:

- [GitHub](https://github.com/Ilias1988)
- [LinkedIn](https://www.linkedin.com/in/ilias-georgopoulos-b491a3371/)
- [X / Twitter](https://x.com/EliotGeo)
- [Cybersecurity portfolio](https://ilias1988.me/)

## License

MIT License. See [`LICENSE`](LICENSE).
