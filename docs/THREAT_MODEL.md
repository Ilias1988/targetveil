# TargetVeil threat model

## Security objective

TargetVeil reduces accidental disclosure of personal data, client infrastructure, secrets and explicitly scoped engagement identifiers when a pentester prepares text for a public AI service.

The security boundary ends at the sanitized-output preview. The user remains responsible for reviewing that output, choosing an approved AI service and complying with the engagement rules.

## Data flow

1. GitHub Pages or a local web server delivers public static assets.
2. On hosted HTML pages, Cloudflare Web Analytics receives ordinary aggregate page-view and performance measurements. The sanitizer defines no custom analytics events and does not pass form or file values to the beacon.
3. The user enters text, imports a supported text evidence file or selects a local scope JSON file.
4. First-party JavaScript reads and processes that data in the current page.
5. Findings and mappings remain in JavaScript memory.
6. The user reviews the sanitized result.
7. Only an explicit action copies the sanitized result or creates a local sanitized download.
8. Reload or **Clear page memory** discards page-held data.

There is no prompt-processing application backend. Prompt data is not added to a URL, network request, cookie or persistent browser storage by TargetVeil's sanitizer.

## Assets to protect

- Customer and employee identities.
- Target domains, hosts, IP addresses and internal topology.
- Usernames, session identifiers, cookies and authorization material.
- API keys, passwords, private keys and connection credentials.
- Project names, case numbers, tenant IDs and other engagement-specific identifiers.
- The local pseudonym-to-original mapping.

## Trust assumptions

- The browser, operating system and device are trusted.
- Installed extensions cannot read or modify the page.
- The static files match the reviewed repository revision.
- On the hosted site, Cloudflare's remotely delivered analytics beacon behaves as documented and is not compromised.
- The user supplies complete engagement-specific values when generic detection is insufficient.
- The user manually reviews output before any third-party transmission.

## Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Application uploads a prompt | No prompt backend; sanitizer/UI contain no network APIs; CSP limits remote scripts and connections to the disclosed Cloudflare analytics hosts; static verification enforces that allowlist | A malicious hosted build or compromised third-party analytics script executes in the page and could violate this boundary |
| Sensitive values persist in browser storage | No application storage API; only public static assets enter Cache Storage | Browser/OS swap, crash diagnostics or extensions are outside the boundary |
| A detector misses a value | Multiple detector classes, scope values, verification pass and manual preview | Unknown or semantic identifiers can remain |
| Regex consumes adjacent structured data | Span overlap resolution and regression corpora for multiline HTTP, forms and JSON | Unseen formats may produce false positives or false negatives |
| Pseudonyms destroy technical relationships | Same-value mapping plus domain-hierarchy and IP-range pseudonyms | Some exact topology detail is intentionally removed |
| Mapping leaks to the model | Mapping remains in page memory and is not exported | User could manually copy an original value or the findings table |
| Local file contains executable markup | Scope is parsed as JSON; evidence is treated as text; user-controlled content is assigned with `textContent` or form values | Large text files can affect performance; scope is limited to 1 MB and evidence to 10 MB |
| XSS exfiltrates data | No HTML rendering of user input and a restrictive CSP | Browser vulnerabilities, malicious extensions and compromise of the permitted analytics script remain possible |
| Analytics collects prompt data | No custom events; no analytics calls in sanitizer/UI; prompt values are not placed in URLs; static checks constrain the analytics integration | The remote beacon executes in page context, so its integrity and Cloudflare's documented behavior are trust assumptions |
| Hosted supply-chain compromise or stale vulnerable assets | Open source, tests on every deployment, network-first static updates with offline cache fallback, disconnected local option | Hosting-account or analytics supply-chain compromise remains possible until detected |

## Non-goals

- Guaranteeing legal anonymization or regulatory compliance.
- Overriding a client's prohibition on third-party AI.
- Protecting data after the user copies it into another application.
- Protecting a compromised endpoint or browser.
- Inspecting images, PDFs, archives or binary files in version 0.2.
- Acting as a transparent interception proxy in version 0.2.

## Safer operating modes

For the most sensitive work:

1. Clone a pinned repository revision.
2. Review the static files and verify their checksums.
3. Disconnect the system from the network.
4. Serve `docs/` from loopback or use the Python CLI.
5. Use a complete engagement scope file.
6. Review the sanitized output manually.
