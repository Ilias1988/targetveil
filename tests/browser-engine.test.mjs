import assert from "node:assert/strict";
import test from "node:test";

import { PROFILE_DEFINITIONS, parseScopeFile, readEvidenceFile, sanitize, scan } from "../docs/engine.js";
import { DEMO_DEFINITIONS } from "../docs/demos.js";

const CANARIES = Object.freeze({
  domain: "portal.acme-pentest.gr",
  email: "analyst@acme-pentest.gr",
  privateIp: "10.20.30.41",
  publicIp: "203.0.113.77",
  password: "SyntheticPass!2026",
  jwt: "eyJhbGciOiJIUzI1NiJ9.c3ludGhldGljLXVzZXI.c3ludGhldGljLXNpZw",
  client: "Acme Pentest Ltd",
});

test("all requested pentest profiles exist", () => {
  for (const name of [
    "burp", "nmap", "nuclei", "ffuf", "bloodhound", "siem", "sqlmap", "web_discovery",
    "netexec", "mimikatz", "metasploit", "wireshark", "vuln_scanner", "cloud", "osint",
  ]) {
    assert.ok(PROFILE_DEFINITIONS[name], `missing ${name}`);
  }
});

test("every profile has a runnable synthetic example with no declared canary leakage", () => {
  assert.deepEqual(new Set(Object.keys(DEMO_DEFINITIONS)), new Set(Object.keys(PROFILE_DEFINITIONS)));
  for (const [name, demo] of Object.entries(DEMO_DEFINITIONS)) {
    const result = sanitize(demo.text, { profile: demo.profile, region: "global" });
    assert.ok(result.findings.length > 0, `${name} demo produced no findings`);
    assert.equal(result.safe, true, `${name} demo failed verification`);
    for (const canary of demo.canaries) {
      assert.equal(result.sanitizedText.includes(canary), false, `${name} demo leaked ${canary}`);
    }
  }
});

test("Burp canary corpus has no target-value leakage", () => {
  const source = `POST https://${CANARIES.domain}/login HTTP/1.1
Host: ${CANARIES.domain}
Authorization: Bearer ${CANARIES.jwt}
Cookie: session=canary-cookie-7788

username=${CANARIES.email}&password=${CANARIES.password}&source=${CANARIES.privateIp}&callback=${CANARIES.publicIp}`;
  const result = sanitize(source, {
    profile: "burp",
    customValues: [{ type: "CLIENT", value: CANARIES.client }],
  });
  for (const canary of Object.values(CANARIES).filter((value) => source.includes(value))) {
    assert.equal(result.sanitizedText.includes(canary), false, `leaked ${canary}`);
  }
  assert.equal(result.safe, true);
  assert.match(result.sanitizedText, /POST https:\/\/sub-\d+\.target-\d+\.example\/login/);
  assert.match(result.sanitizedText, /Authorization: Bearer \{\{REDACTED_AUTH_TOKEN_001\}\}/);
});

test("repeated IPs remain related and same /24 receives same network pseudonym", () => {
  const source = "10.20.30.41 -> 10.20.30.42 -> 10.20.30.41; external 8.8.8.8";
  const result = sanitize(source, { profile: "nmap" });
  const privateHits = result.findings.filter((item) => item.type === "PRIVATE_IP");
  assert.equal(privateHits[0].replacement, privateHits[2].replacement);
  assert.match(privateHits[0].replacement, /PRIVATE_NET_001_HOST_001/);
  assert.match(privateHits[1].replacement, /PRIVATE_NET_001_HOST_002/);
  assert.equal(result.sanitizedText.includes("10.20.30"), false);
});

test("domain hierarchy is pseudonymized consistently without exposing labels", () => {
  const result = sanitize("api.client.gr v1.api.client.gr portal.client.gr", { profile: "burp" });
  assert.equal(result.sanitizedText.includes("client"), false);
  assert.match(result.sanitizedText, /sub-001\.target-001\.example/);
  assert.match(result.sanitizedText, /sub-002\.sub-001\.target-001\.example/);
  assert.match(result.sanitizedText, /sub-003\.target-001\.example/);
});

test("Greek and European identifiers use contextual/checksum validation", () => {
  const source = "ΑΦΜ: 123456783\nΑΜΚΑ: 01019012345\nIBAN: GR6700000000000000000000000\nVAT ID: DE123456789";
  const findings = scan(source, { profile: "strict" });
  const types = new Set(findings.map((item) => item.type));
  assert.ok(types.has("GREEK_AFM"));
  assert.ok(types.has("GREEK_AMKA"));
  assert.ok(types.has("IBAN"));
  assert.ok(types.has("EU_VAT"));
});

test("global country packs detect validated or contextual identifiers", () => {
  const source = [
    "SSN: 123-45-6789",
    "EIN: 12-3456789",
    "NINO: AB 12 34 56 C",
    "SIN: 046 454 286",
    "TFN: 123456782",
    "PAN: ABCDE1234F",
    "Aadhaar: 2345 6789 0124",
    "CPF: 123.456.789-09",
    "passport: X1234567",
    "national id: SYNTH-99172",
  ].join("\n");
  const types = new Set(scan(source, { profile: "strict", region: "global" }).map((item) => item.type));
  for (const expected of [
    "US_SSN", "US_EIN", "UK_NINO", "CANADA_SIN", "AU_TFN", "INDIA_PAN",
    "INDIA_AADHAAR", "BRAZIL_CPF", "PASSPORT_ID", "NATIONAL_ID",
  ]) {
    assert.ok(types.has(expected), `missing ${expected}`);
  }
});

test("regional selection excludes unrelated country identifiers", () => {
  const source = "SSN: 123-45-6789\nΑΦΜ: 123456783\nCPF: 123.456.789-09";
  const types = new Set(scan(source, { profile: "strict", region: "us" }).map((item) => item.type));
  assert.ok(types.has("US_SSN"));
  assert.equal(types.has("GREEK_AFM"), false);
  assert.equal(types.has("BRAZIL_CPF"), false);
});

test("BloodHound profile detects principals, SID, GUID and labeled hosts", () => {
  const source = "ACME\\jdoe S-1-5-21-111111111-222222222-333333333-1105 computer=DC01 6ba7b810-9dad-11d1-80b4-00c04fd430c8";
  const types = new Set(scan(source, { profile: "bloodhound" }).map((item) => item.type));
  assert.ok(types.has("USERNAME"));
  assert.ok(types.has("SID"));
  assert.ok(types.has("LABELED_HOST"));
  assert.ok(types.has("GUID"));
});

test("scope files are parsed locally and apply custom values", () => {
  const scope = parseScopeFile(JSON.stringify({
    engagement: "Demo",
    profile: "siem",
    sensitive_values: [{ type: "CASE_ID", value: "INC-77881" }],
    allowlist: ["example.com"],
  }));
  const result = sanitize("case=INC-77881", { profile: scope.profile, customValues: scope.customValues });
  assert.equal(result.sanitizedText.includes("INC-77881"), false);
  assert.equal(result.findings[0].reason.includes("scope file"), true);
});

test("redact mode uses generic REDACTED markers", () => {
  const result = sanitize("mail me at person@private.gr twice person@private.gr", { profile: "strict", mode: "redact" });
  assert.equal(result.sanitizedText, "mail me at {{REDACTED_EMAIL}} twice {{REDACTED_EMAIL}}");
});

test("JSON credential fields are sanitized", () => {
  const canary = "NeverSendThis-JSON-Secret-991";
  const result = sanitize(`{"username":"alice@private.example.gr","password":"${canary}","client_secret":"also-private"}`, { profile: "burp" });
  assert.equal(result.sanitizedText.includes(canary), false);
  assert.equal(result.sanitizedText.includes("also-private"), false);
  assert.equal(result.counts.SECRET, 2);
  assert.equal(result.safe, true);
});

test("database profiles remove URI and connection-string credentials", () => {
  const source = [
    "postgresql://dbadmin:DbCanary-9981@sql.prod-client.net:5432/customer",
    "Server=10.70.1.9;User Id=report_user;Password=SqlCanary-772;Database=prod",
  ].join("\n");
  const result = sanitize(source, { profile: "sqlmap" });
  for (const canary of ["dbadmin", "DbCanary-9981", "sql.prod-client.net", "10.70.1.9", "report_user", "SqlCanary-772"]) {
    assert.equal(result.sanitizedText.includes(canary), false, `database canary leaked: ${canary}`);
  }
  assert.ok(result.findings.some((item) => item.type === "DATABASE_USER"));
  assert.ok(result.findings.some((item) => item.detector === "database-uri-password"));
  assert.equal(result.safe, true);
});

test("AD credential-tool profiles remove users, hashes, hosts and addresses", () => {
  const hash = "8846f7eaee8fb117ad06bdd830b7586c";
  const source = [
    "SMB 10.50.2.14 445 DC-CLIENT [+] CLIENT\\svc_backup:WinterCanary!",
    "Username : svc_backup",
    `NTLM : ${hash}`,
    "S-1-5-21-111111111-222222222-333333333-1109",
  ].join("\n");
  const result = sanitize(source, { profile: "netexec" });
  for (const canary of ["10.50.2.14", "CLIENT\\svc_backup", "svc_backup", hash]) {
    assert.equal(result.sanitizedText.includes(canary), false, `AD canary leaked: ${canary}`);
  }
  assert.ok(result.findings.some((item) => item.type === "NTLM_HASH"));
  assert.equal(result.safe, true);
});

test("cloud profile removes AWS, Azure, GCP and kubeconfig identifiers", () => {
  const values = [
    "123456789012",
    "arn:aws:iam::123456789012:role/PentestClientAdmin",
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "private-prod-77881",
    "ZXlKaGJHY2lPaUpTVXpJMU5pSjkuY2FuYXJ5",
    "AKIAIOSFODNN7EXAMPLE",
  ];
  const source = [
    `AWS account ID: ${values[0]}`,
    `role=${values[1]}`,
    `tenant_id=${values[2]}`,
    `project_id=${values[3]}`,
    `token: ${values[4]}`,
    `aws_access_key_id=${values[5]}`,
  ].join("\n");
  const result = sanitize(source, { profile: "cloud" });
  for (const canary of values) assert.equal(result.sanitizedText.includes(canary), false, `cloud canary leaked: ${canary}`);
  const types = new Set(result.findings.map((item) => item.type));
  for (const expected of ["CLOUD_ACCOUNT", "CLOUD_RESOURCE", "AZURE_ID", "K8S_SECRET", "API_KEY"]) {
    assert.ok(types.has(expected), `missing cloud type ${expected}`);
  }
  assert.equal(result.safe, true);
});

test("expanded API-key corpus is detected without treating arbitrary strings as keys", () => {
  const keys = [
    "glpat-" + "abcdefghijklmnopqrst",
    "sk" + "_live_" + "abcdefghijklmnopqrstuvwx",
    "AIza" + "SyA12345678901234567890123456789012",
    "SK" + "0123456789abcdef0123456789abcdef",
  ];
  const result = sanitize(keys.join("\n"), { profile: "strict" });
  for (const key of keys) assert.equal(result.sanitizedText.includes(key), false, `API key leaked: ${key}`);
  assert.equal(scan("release-id=abcdefghijklmnopqrstuvwx", { profile: "strict" }).some((item) => item.type === "API_KEY"), false);
});

test("compressed IPv6 addresses are recognized and repeated values stay consistent", () => {
  const source = "src=fd00:42::19 dst=2001:db8:85a3::8a2e:370:7334 again=fd00:42::19";
  const result = sanitize(source, { profile: "wireshark" });
  assert.equal(result.sanitizedText.includes("fd00:42::19"), false);
  assert.equal(result.sanitizedText.includes("2001:db8:85a3::8a2e:370:7334"), false);
  const privateHits = result.findings.filter((item) => item.value === "fd00:42::19");
  assert.equal(privateHits.length, 2);
  assert.equal(privateHits[0].replacement, privateHits[1].replacement);
});

test("local evidence reader accepts text exports and rejects binary or oversized input", async () => {
  const evidence = await readEvidenceFile({ name: "scan.nessus", size: 20, text: async () => "host=10.1.2.3" });
  assert.equal(evidence.name, "scan.nessus");
  assert.equal(evidence.text, "host=10.1.2.3");
  await assert.rejects(() => readEvidenceFile({ name: "dump.bin", size: 4, text: async () => "test" }), /Unsupported/);
  await assert.rejects(() => readEvidenceFile({ name: "large.log", size: 100, text: async () => "test" }, 50), /exceeds/);
  await assert.rejects(() => readEvidenceFile({ name: "binary.log", size: 4, text: async () => "a\u0000b" }), /Binary/);
});

test("common technical literals remain unchanged in balanced mode", () => {
  const source = "HTTP/1.1 200 OK\nContent-Type: application/json\nCVE-2026-12345\nport=443\nversion=10.2.4";
  const result = sanitize(source, { profile: "balanced" });
  assert.equal(result.sanitizedText, source);
  assert.equal(result.findings.length, 0);
});

test("one-megabyte log corpus completes within a practical browser budget", () => {
  const line = "INFO port=443 status=200 src=10.44.55.66 host=portal.synthetic-client.net user=analyst@synthetic-client.net\n";
  const source = line.repeat(Math.ceil(1024 * 1024 / line.length));
  const started = performance.now();
  const result = sanitize(source, { profile: "siem" });
  const elapsed = performance.now() - started;
  assert.equal(result.safe, true);
  assert.equal(result.sanitizedText.includes("synthetic-client.net"), false);
  assert.ok(elapsed < 5000, `sanitization took ${elapsed.toFixed(0)} ms`);
});

test("HTTP method, path, headers, delimiters and JSON body structure are preserved", () => {
  const source = `PATCH /api/users/7?expand=roles HTTP/1.1\r
Host: accounts.private-client.net\r
Content-Type: application/json\r
X-Trace-Mode: verbose\r
\r
{"username":"owner@private-client.net","password":"BodyCanary-441","active":true}`;
  const result = sanitize(source, { profile: "burp" });
  assert.match(result.sanitizedText, /^PATCH \/api\/users\/7\?expand=roles HTTP\/1\.1\r\n/);
  assert.match(result.sanitizedText, /\r\nContent-Type: application\/json\r\nX-Trace-Mode: verbose\r\n\r\n/);
  const body = result.sanitizedText.split("\r\n\r\n")[1];
  const parsed = JSON.parse(body);
  assert.equal(parsed.active, true);
  assert.match(parsed.username, /^user-\d+@target-\d+\.example$/);
  assert.match(parsed.password, /^\{\{REDACTED_SECRET_\d+\}\}$/);
  assert.equal(result.safe, true);
});

test("Unicode and punctuation fuzz corpus never throws or changes non-sensitive text", () => {
  const fragments = ["αβγ", "日本語", "🔐", "[]{}()", "../etc/passwd", "%2Fapi%2Fv1", "CVE-2026-9999", "—", "\u2028"];
  for (let index = 0; index < 250; index += 1) {
    const source = fragments.map((item, offset) => `${item}${index + offset}`).join(" | ");
    const result = sanitize(source, { profile: "balanced" });
    assert.equal(result.sanitizedText, source);
    assert.equal(result.safe, true);
  }
});

test("allowlist matching is exact and case-insensitive", () => {
  const source = "SAFE.CLIENT.NET api.safe.client.net 10.4.5.6";
  const result = sanitize(source, { profile: "nmap", allowlist: ["safe.client.net", "10.4.5.6"] });
  assert.ok(result.sanitizedText.includes("SAFE.CLIENT.NET"));
  assert.ok(result.sanitizedText.includes("10.4.5.6"));
  assert.equal(result.sanitizedText.includes("api.safe.client.net"), false);
});
