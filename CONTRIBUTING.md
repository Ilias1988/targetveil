# Contributing to TargetVeil

Thank you for helping improve privacy for AI-assisted security work.

## Ground rules

- Use TargetVeil and its test material only for authorized security work.
- Never commit real client names, IP addresses, domains, tokens, logs, screenshots or personal identifiers.
- Use obvious synthetic values and reserved/example domains.
- New detectors must document why the data is sensitive and how false positives are limited.
- Prefer label context, format validation or checksums over broad numeric regular expressions.
- Every detector change must add positive, negative and leakage regression tests.
- Do not add remote models, prompt persistence, custom analytics events or additional third-party scripts/CDNs. The only approved hosted-site analytics dependency is the declared Cloudflare Web Analytics beacon; sanitizer and prompt data must never be passed to it.

## Development

The browser engine has no runtime dependencies:

```bash
npm test
node scripts/verify-static.mjs
npm run test:e2e
```

Run Python tests without installing:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p "test_*.py" -v
```

On PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -p "test_*.py" -v
```

Preview the website:

```bash
python -m http.server 4173 --directory docs --bind 127.0.0.1
```

## Adding a country pack

1. Use an authoritative description of the identifier format.
2. Require an explicit label when the raw shape is ambiguous.
3. Implement the official checksum when one exists.
4. Add the type to `REGIONAL_TYPES`.
5. Add at least one synthetic positive, invalid-checksum negative and cross-region exclusion test.
6. Update the coverage table in the README and visible site copy.

## Pull requests

Explain the privacy problem, the chosen false-positive controls and the test evidence. A pull request must pass browser tests, Python tests, static privacy verification and the real-browser end-to-end suite before Pages deployment.
