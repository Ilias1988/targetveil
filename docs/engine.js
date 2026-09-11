/**
 * TargetVeil browser engine.
 * Pure JavaScript, no network calls, no storage and no third-party dependencies.
 */

export const PROFILE_DEFINITIONS = Object.freeze({
  balanced: {
    label: "Balanced",
    group: "General",
    description: "General pentest text with lower detection noise.",
    types: "all",
  },
  burp: {
    label: "Burp / HTTP",
    group: "Web application",
    description: "HTTP requests, responses, cookies, tokens and web targets.",
    types: "all",
  },
  nmap: {
    label: "Nmap",
    group: "Network",
    description: "IPs, DNS names, MAC addresses and scope values.",
    types: new Set(["PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "MAC_ADDRESS", "CUSTOM"]),
  },
  nuclei: {
    label: "Nuclei",
    group: "Vulnerability scanning",
    description: "Targets, URLs, authentication data and template output.",
    types: new Set([
      "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "AUTH_TOKEN", "COOKIE", "SECRET",
      "JWT", "API_KEY", "USERNAME", "CUSTOM",
    ]),
  },
  ffuf: {
    label: "ffuf",
    group: "Web application",
    description: "Target hosts, URLs, headers, cookies and credentials.",
    types: new Set([
      "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "AUTH_TOKEN", "COOKIE", "SECRET",
      "JWT", "API_KEY", "USERNAME", "CUSTOM",
    ]),
  },
  bloodhound: {
    label: "BloodHound / AD",
    group: "Windows / Active Directory",
    description: "AD domains, principals, SIDs, GUIDs, hosts and addresses.",
    types: new Set([
      "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "USERNAME", "PERSON", "SID", "GUID",
      "LABELED_HOST", "MAC_ADDRESS", "CUSTOM",
    ]),
  },
  siem: {
    label: "SIEM / Logs",
    group: "Logs / incident response",
    description: "Log identities, hosts, network indicators and secrets.",
    types: "all",
  },
  sqlmap: {
    label: "sqlmap / Database",
    group: "Web application",
    description: "SQL injection output, database connection strings and credentials.",
    types: new Set([
      "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "AUTH_TOKEN", "COOKIE", "SECRET",
      "JWT", "API_KEY", "USERNAME", "DATABASE_USER", "CUSTOM",
    ]),
  },
  web_discovery: {
    label: "Gobuster / Nikto / WPScan",
    group: "Web application",
    description: "Web discovery output, target URLs, headers and credentials.",
    types: new Set([
      "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "AUTH_TOKEN", "COOKIE", "SECRET",
      "JWT", "API_KEY", "USERNAME", "CUSTOM",
    ]),
  },
  netexec: {
    label: "NetExec / Impacket",
    group: "Windows / Active Directory",
    description: "SMB, LDAP and Kerberos output, principals, hosts and credential material.",
    types: new Set([
      "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "USERNAME", "SECRET", "NTLM_HASH", "SID",
      "GUID", "LABELED_HOST", "MAC_ADDRESS", "CUSTOM",
    ]),
  },
  mimikatz: {
    label: "Mimikatz / Secretsdump",
    group: "Windows / Active Directory",
    description: "Credential-dump output, account names, domains and password hashes.",
    types: new Set(["DOMAIN", "USERNAME", "SECRET", "NTLM_HASH", "SID", "GUID", "CUSTOM"]),
  },
  metasploit: {
    label: "Metasploit",
    group: "Exploitation",
    description: "Console output, sessions, network targets, credentials and loot references.",
    types: "all",
  },
  wireshark: {
    label: "Wireshark / tcpdump",
    group: "Network",
    description: "Packet text exports with IPs, MACs, DNS names and application credentials.",
    types: new Set([
      "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "MAC_ADDRESS", "EMAIL", "AUTH_TOKEN", "COOKIE",
      "SECRET", "JWT", "API_KEY", "CUSTOM",
    ]),
  },
  vuln_scanner: {
    label: "Nessus / OpenVAS",
    group: "Vulnerability scanning",
    description: "Scanner exports with affected hosts, services, evidence and credentials.",
    types: "all",
  },
  cloud: {
    label: "AWS / Azure / GCP / Kubernetes",
    group: "Cloud / containers",
    description: "Cloud resource identifiers, tenants, projects, kubeconfig secrets and API keys.",
    types: new Set([
      "PRIVATE_IP", "PUBLIC_IP", "DOMAIN", "EMAIL", "USERNAME", "SECRET", "API_KEY", "JWT",
      "CLOUD_ACCOUNT", "CLOUD_RESOURCE", "AZURE_ID", "K8S_SECRET", "GUID", "CUSTOM",
    ]),
  },
  osint: {
    label: "OSINT / Recon",
    group: "Reconnaissance",
    description: "People, accounts, contact details, domains and public infrastructure.",
    types: new Set([
      "PUBLIC_IP", "DOMAIN", "EMAIL", "USERNAME", "PHONE", "PERSON", "ADDRESS",
      "PASSPORT_ID", "NATIONAL_ID", "CUSTOM",
    ]),
  },
  strict: {
    label: "Strict",
    group: "General",
    description: "All detectors, including loopback and test-like values.",
    types: "all",
  },
});

export const REGION_DEFINITIONS = Object.freeze({
  global: "Global — all available country packs",
  eu: "European Union / EEA",
  gr: "Greece",
  us: "United States",
  uk: "United Kingdom",
  ca: "Canada",
  au: "Australia",
  in: "India",
  br: "Brazil",
});

const REGIONAL_TYPES = Object.freeze({
  GREEK_AFM: new Set(["global", "eu", "gr"]),
  GREEK_AMKA: new Set(["global", "eu", "gr"]),
  EU_VAT: new Set(["global", "eu", "gr"]),
  US_SSN: new Set(["global", "us"]),
  US_EIN: new Set(["global", "us"]),
  UK_NINO: new Set(["global", "uk"]),
  CANADA_SIN: new Set(["global", "ca"]),
  AU_TFN: new Set(["global", "au"]),
  INDIA_PAN: new Set(["global", "in"]),
  INDIA_AADHAAR: new Set(["global", "in"]),
  BRAZIL_CPF: new Set(["global", "br"]),
});

const REASONS = Object.freeze({
  PRIVATE_KEY: "A private key could allow unauthorized access.",
  AUTH_TOKEN: "Credential found inside an HTTP Authorization header.",
  COOKIE: "HTTP cookie that may contain an active session identifier.",
  SECRET: "Value assigned to a password, secret or access-token field.",
  JWT: "JSON Web Token that may contain identity claims or active authorization.",
  API_KEY: "Value matching a known API or access-key format.",
  EMAIL: "Email address that may identify a person or engagement target.",
  PRIVATE_IP: "Private IP address that reveals internal target topology.",
  PUBLIC_IP: "Public IP address that may identify client infrastructure.",
  MAC_ADDRESS: "MAC address that identifies a network interface.",
  DOMAIN: "Domain or hostname that may identify the assessment target.",
  USERNAME: "Username or account principal.",
  PHONE: "Telephone number that may identify a person.",
  CREDIT_CARD: "Payment-card number that passed Luhn validation.",
  GREEK_AFM: "Greek tax identifier that passed checksum validation.",
  GREEK_AMKA: "Greek social-security identifier in a labeled field.",
  IBAN: "International Bank Account Number that passed mod-97 validation.",
  EU_VAT: "European VAT identifier in a labeled field.",
  US_SSN: "US Social Security Number in a labeled field.",
  US_EIN: "US Employer Identification Number in a labeled field.",
  UK_NINO: "UK National Insurance Number in a labeled field.",
  CANADA_SIN: "Canadian Social Insurance Number that passed Luhn validation.",
  AU_TFN: "Australian Tax File Number that passed weighted-checksum validation.",
  INDIA_PAN: "Indian Permanent Account Number in a labeled field.",
  INDIA_AADHAAR: "Indian Aadhaar number that passed Verhoeff validation.",
  BRAZIL_CPF: "Brazilian CPF that passed both checksum digits.",
  PASSPORT_ID: "Passport identifier found in an explicitly labeled field.",
  NATIONAL_ID: "National identity number found in an explicitly labeled field.",
  PERSON: "Person name found in an explicitly labeled field.",
  ADDRESS: "Postal address found in an explicitly labeled field.",
  SID: "Windows or Active Directory security identifier.",
  GUID: "GUID that may identify a tenant or directory object in this profile.",
  LABELED_HOST: "Host or computer value in an explicitly labeled log field.",
  DATABASE_USER: "Database username embedded in a connection URI or connection string.",
  NTLM_HASH: "NTLM or NT password hash found in credential-dump output.",
  CLOUD_ACCOUNT: "Cloud account identifier that may reveal the assessed organization.",
  CLOUD_RESOURCE: "Cloud resource identifier that may reveal target infrastructure.",
  AZURE_ID: "Azure tenant, subscription or directory-object identifier in a labeled field.",
  K8S_SECRET: "Kubernetes credential or certificate material in a kubeconfig-style field.",
  CUSTOM: "Sensitive value declared in the engagement scope.",
});

const FILELIKE_SUFFIXES = new Set([
  "bash", "conf", "config", "css", "csv", "env", "go", "gz", "html", "ini", "java",
  "jpeg", "jpg", "js", "json", "log", "md", "pem", "php", "png", "ps1", "py", "rb",
  "sh", "sql", "svg", "tar", "toml", "ts", "txt", "xml", "yaml", "yml", "zip",
]);
const SAFE_DOMAINS = new Set(["example.com", "example.net", "example.org", "localhost"]);
const COMMON_MULTI_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "com.gr", "net.gr", "org.gr", "gov.gr",
  "com.cy", "com.de", "com.fr", "com.es", "com.it", "com.nl",
]);

function finding(type, value, start, detector, confidence = 1, priority = 50, normalized = null) {
  return {
    type,
    value,
    start,
    end: start + value.length,
    detector,
    confidence,
    priority,
    normalized: normalized ?? value,
    reason: REASONS[type] ?? REASONS.CUSTOM,
  };
}

function addMatches(target, text, regex, type, detector, options = {}) {
  regex.lastIndex = 0;
  let match;
  while ((match = regex.exec(text)) !== null) {
    const group = options.group ?? 0;
    const value = match[group];
    if (!value) continue;
    const relative = match[0].indexOf(value);
    const start = match.index + Math.max(0, relative);
    if (options.validate && !options.validate(value, match)) continue;
    target.push(finding(
      type,
      value,
      start,
      detector,
      options.confidence ?? 1,
      options.priority ?? 50,
      options.normalize ? options.normalize(value) : value,
    ));
  }
}

function validIPv4(value) {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function privateIPv4(value) {
  const [a, b] = value.split(".").map(Number);
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
}

function validIPv6(value) {
  const normalized = value.toLowerCase();
  if (normalized.includes(".")) return false;
  if ((normalized.match(/::/g) ?? []).length > 1) return false;
  const groups = normalized.split(":");
  const nonEmpty = groups.filter(Boolean);
  if (!nonEmpty.every((group) => /^[0-9a-f]{1,4}$/.test(group))) return false;
  return normalized.includes("::") ? nonEmpty.length < 8 : groups.length === 8;
}

function privateIPv6(value) {
  const normalized = value.toLowerCase();
  return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || /^fe[89ab]/.test(normalized);
}

function luhnValid(value) {
  const digits = value.replace(/\D/g, "").split("").map(Number);
  if (digits.length < 13 || digits.length > 19 || new Set(digits).size === 1) return false;
  let sum = 0;
  const parity = digits.length % 2;
  digits.forEach((raw, index) => {
    let digit = raw;
    if (index % 2 === parity) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  });
  return sum % 10 === 0;
}

function canadaSinValid(value) {
  const digits = value.replace(/\D/g, "");
  if (!/^\d{9}$/.test(digits) || new Set(digits).size === 1) return false;
  let sum = 0;
  [...digits].forEach((raw, index) => {
    let digit = Number(raw);
    if (index % 2 === 1) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  });
  return sum % 10 === 0;
}

function afmValid(value) {
  if (!/^\d{9}$/.test(value) || new Set(value).size === 1) return false;
  let total = 0;
  for (let index = 0; index < 8; index += 1) {
    total += Number(value[index]) * (2 ** (8 - index));
  }
  return total % 11 % 10 === Number(value[8]);
}

function ibanValid(value) {
  const compact = value.replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) return false;
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const character of rearranged) {
    const expansion = /[A-Z]/.test(character) ? String(character.charCodeAt(0) - 55) : character;
    for (const digit of expansion) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

function cpfValid(value) {
  const digits = value.replace(/\D/g, "");
  if (!/^\d{11}$/.test(digits) || new Set(digits).size === 1) return false;
  const check = (length) => {
    let sum = 0;
    for (let i = 0; i < length; i += 1) sum += Number(digits[i]) * (length + 1 - i);
    const remainder = (sum * 10) % 11;
    return (remainder === 10 ? 0 : remainder) === Number(digits[length]);
  };
  return check(9) && check(10);
}

function australianTfnValid(value) {
  const compact = value.replace(/\s/g, "");
  if (!/^\d{8,9}$/.test(compact)) return false;
  const digits = (compact.length === 8 ? `0${compact}` : compact).split("").map(Number);
  const weights = [1, 4, 3, 7, 5, 8, 6, 9, 10];
  return digits.reduce((sum, digit, index) => sum + digit * weights[index], 0) % 11 === 0;
}

const VERHOEFF_D = [
  [0,1,2,3,4,5,6,7,8,9], [1,2,3,4,0,6,7,8,9,5], [2,3,4,0,1,7,8,9,5,6],
  [3,4,0,1,2,8,9,5,6,7], [4,0,1,2,3,9,5,6,7,8], [5,9,8,7,6,0,4,3,2,1],
  [6,5,9,8,7,1,0,4,3,2], [7,6,5,9,8,2,1,0,4,3], [8,7,6,5,9,3,2,1,0,4],
  [9,8,7,6,5,4,3,2,1,0],
];
const VERHOEFF_P = [
  [0,1,2,3,4,5,6,7,8,9], [1,5,7,6,2,8,3,0,9,4], [5,8,0,3,7,9,6,1,4,2],
  [8,9,1,6,0,4,3,5,2,7], [9,4,5,3,1,2,6,8,7,0], [4,2,8,6,5,7,3,9,0,1],
  [2,7,9,3,8,0,6,4,1,5], [7,0,4,6,9,1,3,2,5,8],
];

function verhoeffValid(value) {
  const digits = value.replace(/\s/g, "");
  if (!/^\d+$/.test(digits)) return false;
  let checksum = 0;
  [...digits].reverse().forEach((digit, index) => {
    checksum = VERHOEFF_D[checksum][VERHOEFF_P[index % 8][Number(digit)]];
  });
  return checksum === 0;
}

function detectAll(text, strict) {
  const found = [];
  addMatches(found, text, /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g, "PRIVATE_KEY", "private-key", { priority: 100 });
  addMatches(found, text, /^[ \t]*authorization[ \t]*:[ \t]*(?:bearer|basic|digest)[ \t]+([^\s\r\n]+)/gim, "AUTH_TOKEN", "authorization-header", { group: 1, priority: 95 });
  addMatches(found, text, /^[ \t]*(?:set-)?cookie[ \t]*:[ \t]*([^\s\r\n][^\r\n]*)/gim, "COOKIE", "cookie-header", { group: 1, priority: 94 });
  addMatches(found, text, /(?:password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|session[_-]?id|aws[_-]?secret[_-]?access[_-]?key)["']?[ \t]*[=:][ \t]*["']?([^&\s"',;}{]+)/gi, "SECRET", "sensitive-field", { group: 1, priority: 92 });
  addMatches(found, text, /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])/g, "JWT", "jwt", { priority: 91 });
  addMatches(found, text, /(?<![A-Za-z0-9])(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|glpat-[A-Za-z0-9_-]{20,255}|xox[baprs]-[A-Za-z0-9-]{10,255}|(?:sk|rk)_live_[A-Za-z0-9]{16,255}|AIza[0-9A-Za-z_-]{35}|SK[0-9a-fA-F]{32}|sk-[A-Za-z0-9_-]{20,255})(?![A-Za-z0-9])/g, "API_KEY", "api-key", { priority: 90 });
  addMatches(found, text, /\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{20,255}/g, "API_KEY", "discord-webhook", { priority: 90 });
  addMatches(found, text, /(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}(?![\w.-])/gi, "EMAIL", "email", { priority: 80, normalize: (v) => v.toLowerCase() });

  const ipv4 = /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])/g;
  ipv4.lastIndex = 0;
  let ipMatch;
  while ((ipMatch = ipv4.exec(text)) !== null) {
    const value = ipMatch[0];
    if (!validIPv4(value)) continue;
    const loopbackOrZero = value.startsWith("127.") || value === "0.0.0.0";
    if (loopbackOrZero && !strict) continue;
    const type = privateIPv4(value) ? "PRIVATE_IP" : "PUBLIC_IP";
    found.push(finding(type, value, ipMatch.index, "ipv4", 1, 75, value));
  }

  const ipv6 = /(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])/gi;
  ipv6.lastIndex = 0;
  let ipv6Match;
  while ((ipv6Match = ipv6.exec(text)) !== null) {
    const value = ipv6Match[0];
    if (!validIPv6(value) || (value === "::1" && !strict)) continue;
    const type = privateIPv6(value) ? "PRIVATE_IP" : "PUBLIC_IP";
    found.push(finding(type, value, ipv6Match.index, "ipv6", 1, 75, value.toLowerCase()));
  }
  addMatches(found, text, /(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])/gi, "MAC_ADDRESS", "mac", { priority: 75, normalize: (v) => v.toLowerCase() });

  const domain = /(?<![\w@])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|local|internal|lan|corp)(?![\w.-])/gi;
  domain.lastIndex = 0;
  let domainMatch;
  while ((domainMatch = domain.exec(text)) !== null) {
    const value = domainMatch[0].replace(/\.$/, "");
    const normalized = value.toLowerCase();
    const suffix = normalized.split(".").at(-1);
    if (SAFE_DOMAINS.has(normalized) || normalized.endsWith(".example") || FILELIKE_SUFFIXES.has(suffix)) continue;
    found.push(finding("DOMAIN", value, domainMatch.index, "domain", 1, 70, normalized));
  }

  addMatches(found, text, /(?:user(?:name)?|login|account)["']?[ \t]*[=:][ \t]*["']?([^&\s"',;}{]+)/gi, "USERNAME", "username-field", {
    group: 1,
    priority: 78,
    validate: (value) => strict || !new Set(["admin", "administrator", "root", "guest", "test"]).has(value.toLowerCase()),
  });
  addMatches(found, text, /(?<![\w])(?:[A-Z0-9._-]+\\[A-Z0-9.$_-]+)(?![\w])/gi, "USERNAME", "ad-principal", { priority: 79, normalize: (v) => v.toLowerCase() });
  addMatches(found, text, /(?:[A-Z]:\\Users\\|\/home\/)([^\\/\s]+)/gi, "USERNAME", "home-path-user", { group: 1, priority: 76, normalize: (v) => v.toLowerCase() });
  addMatches(found, text, /(?:user(?:[ \t_-]*name)?|login)[ \t]*:[ \t]*([^\s*][^\r\n]{0,63}?)(?=[ \t]*$)/gim, "USERNAME", "credential-dump-user", {
    group: 1,
    priority: 83,
    normalize: (v) => v.trim().toLowerCase(),
    validate: (value) => value.trim().length >= 2 && (strict || !new Set(["null", "none", "(null)"]).has(value.trim().toLowerCase())),
  });
  addMatches(found, text, /(?:NTLM|NT[ \t]+hash|nthash)[ \t]*:[ \t]*([a-f0-9]{32})(?![a-f0-9])/gi, "NTLM_HASH", "ntlm-hash-context", { group: 1, priority: 96, normalize: (v) => v.toLowerCase() });

  addMatches(found, text, /(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql):\/\/([^:\s\/@]+):(?=[^@\s]+@)/gi, "DATABASE_USER", "database-uri-user", { group: 1, priority: 88, normalize: (v) => v.toLowerCase() });
  addMatches(found, text, /(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql):\/\/[^:\s\/@]+:([^@\s]+)@/gi, "SECRET", "database-uri-password", { group: 1, priority: 97 });
  addMatches(found, text, /(?:User[ \t]+Id|UID)[ \t]*=[ \t]*([^;\r\n]+)/gi, "DATABASE_USER", "connection-string-user", { group: 1, priority: 87, normalize: (v) => v.trim().toLowerCase() });
  addMatches(found, text, /(?:Password|PWD)[ \t]*=[ \t]*([^;\r\n]+)/gi, "SECRET", "connection-string-password", { group: 1, priority: 97 });

  addMatches(found, text, /(?:AWS[ \t_-]*account(?:[ \t_-]*id)?|accountId)["']?[ \t]*[=:][ \t]*["']?(\d{12})(?!\d)/gi, "CLOUD_ACCOUNT", "aws-account-context", { group: 1, priority: 86 });
  addMatches(found, text, /(?<![A-Za-z0-9])arn:(?:aws|aws-us-gov|aws-cn):[A-Za-z0-9-]*:[A-Za-z0-9-]*:\d{12}:[^\s"']+/g, "CLOUD_RESOURCE", "aws-arn", { priority: 89 });
  addMatches(found, text, /(?:tenant(?:[ \t_-]*id)?|subscription(?:[ \t_-]*id)?|object(?:[ \t_-]*id)?)["']?[ \t]*[=:][ \t]*["']?([A-F0-9]{8}-[A-F0-9]{4}-[1-5][A-F0-9]{3}-[89AB][A-F0-9]{3}-[A-F0-9]{12})/gi, "AZURE_ID", "azure-id-context", { group: 1, priority: 90, normalize: (v) => v.toLowerCase() });
  addMatches(found, text, /(?:project(?:[ \t_-]*id)?|gcp[ \t_-]*project)["']?[ \t]*[=:][ \t]*["']?([a-z][a-z0-9-]{5,29})(?![a-z0-9-])/gi, "CLOUD_RESOURCE", "gcp-project-context", { group: 1, priority: 85, normalize: (v) => v.toLowerCase() });
  addMatches(found, text, /^[ \t]*(?:token|client-key-data|client-certificate-data)[ \t]*:[ \t]*([^\s#][^\r\n#]*)/gim, "K8S_SECRET", "kubeconfig-secret", { group: 1, priority: 98, normalize: (v) => v.trim() });
  addMatches(found, text, /(?<!\d)(?:\+?30[ .-]?)?(?:2\d{9}|69\d{8})(?!\d)/g, "PHONE", "greek-phone", { priority: 65 });
  addMatches(found, text, /(?<!\d)\+\d{1,3}[ .-]?(?:\(?\d{2,4}\)?[ .-]?){2,4}\d{2,4}(?!\d)/g, "PHONE", "international-phone", { priority: 64 });
  addMatches(found, text, /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g, "CREDIT_CARD", "credit-card-luhn", { priority: 85, validate: luhnValid });
  addMatches(found, text, /(?:ΑΦΜ|AFM|VAT(?:\s+number)?)\s*[:=]?\s*(\d{9})(?!\d)/gi, "GREEK_AFM", "greek-afm", { group: 1, priority: 85, validate: afmValid });
  addMatches(found, text, /(?:ΑΜΚΑ|AMKA)\s*[:=]?\s*(\d{11})(?!\d)/gi, "GREEK_AMKA", "greek-amka", { group: 1, priority: 85 });
  addMatches(found, text, /(?<![A-Z0-9])([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30})(?![A-Z0-9])/gi, "IBAN", "iban-mod97", { group: 1, priority: 86, validate: ibanValid, normalize: (v) => v.replace(/\s/g, "").toUpperCase() });
  addMatches(found, text, /(?:EU\s+VAT|VAT\s+ID|VAT\s+number|ΑΦΜ)\s*[:=]?\s*([A-Z]{2}[A-Z0-9]{8,12})(?![A-Z0-9])/gi, "EU_VAT", "eu-vat-context", { group: 1, priority: 82, normalize: (v) => v.toUpperCase() });
  addMatches(found, text, /(?:SSN|Social[ \t]+Security(?:[ \t]+Number)?)[ \t]*[:=]?[ \t]*(\d{3}-\d{2}-\d{4})(?!\d)/gi, "US_SSN", "us-ssn-context", { group: 1, priority: 88, validate: (v) => !/^(000|666|9\d\d)-|-(00)-|-(0000)$/.test(v) });
  addMatches(found, text, /(?:EIN|Employer[ \t]+Identification(?:[ \t]+Number)?)[ \t]*[:=]?[ \t]*(\d{2}-\d{7})(?!\d)/gi, "US_EIN", "us-ein-context", { group: 1, priority: 84 });
  addMatches(found, text, /(?:NINO|National[ \t]+Insurance(?:[ \t]+Number)?)[ \t]*[:=]?[ \t]*([ABCEGHJKLMNPRSTWXYZ]{2}[ \t]?\d{2}[ \t]?\d{2}[ \t]?\d{2}[ \t]?[ABCD])(?![A-Z0-9])/gi, "UK_NINO", "uk-nino-context", { group: 1, priority: 86, normalize: (v) => v.replace(/\s/g, "").toUpperCase() });
  addMatches(found, text, /(?:SIN|Social[ \t]+Insurance(?:[ \t]+Number)?)[ \t]*[:=]?[ \t]*(\d{3}[ -]?\d{3}[ -]?\d{3})(?!\d)/gi, "CANADA_SIN", "canada-sin-luhn", { group: 1, priority: 86, validate: canadaSinValid, normalize: (v) => v.replace(/\D/g, "") });
  addMatches(found, text, /(?:TFN|Tax[ \t]+File(?:[ \t]+Number)?)[ \t]*[:=]?[ \t]*(\d{3}[ ]?\d{3}[ ]?\d{2,3})(?!\d)/gi, "AU_TFN", "australia-tfn-checksum", { group: 1, priority: 86, validate: australianTfnValid, normalize: (v) => v.replace(/\s/g, "") });
  addMatches(found, text, /(?:PAN|Permanent[ \t]+Account(?:[ \t]+Number)?)[ \t]*[:=]?[ \t]*([A-Z]{5}\d{4}[A-Z])(?![A-Z0-9])/gi, "INDIA_PAN", "india-pan-context", { group: 1, priority: 86, normalize: (v) => v.toUpperCase() });
  addMatches(found, text, /(?:Aadhaar|UIDAI)[ \t]*(?:number|no\.?)?[ \t]*[:=]?[ \t]*(\d{4}[ ]?\d{4}[ ]?\d{4})(?!\d)/gi, "INDIA_AADHAAR", "india-aadhaar-verhoeff", { group: 1, priority: 88, validate: verhoeffValid, normalize: (v) => v.replace(/\s/g, "") });
  addMatches(found, text, /(?:CPF|Cadastro[ \t]+de[ \t]+Pessoas[ \t]+Físicas)[ \t]*[:=]?[ \t]*(\d{3}\.?\d{3}\.?\d{3}-?\d{2})(?!\d)/gi, "BRAZIL_CPF", "brazil-cpf-checksum", { group: 1, priority: 88, validate: cpfValid, normalize: (v) => v.replace(/\D/g, "") });
  addMatches(found, text, /(?:passport|passport[ \t]+number|διαβατήριο)[ \t]*[:=]?[ \t]*([A-Z0-9]{5,20})(?![A-Z0-9])/gi, "PASSPORT_ID", "passport-context", { group: 1, priority: 82, normalize: (v) => v.toUpperCase() });
  addMatches(found, text, /(?:national[ \t]+id|identity[ \t]+number|citizen[ \t]+id)[ \t]*[:=]?[ \t]*([A-Z0-9][A-Z0-9 .-]{4,24})(?=$|[\r\n,;])/gim, "NATIONAL_ID", "national-id-context", { group: 1, priority: 81, normalize: (v) => v.replace(/[ .-]/g, "").toUpperCase() });
  addMatches(found, text, /^\s*(?:full\s+name|first\s+name|last\s+name|contact|όνομα|επώνυμο|ονοματεπώνυμο)\s*[:=]\s*([^\r\n,;]{2,100})/gim, "PERSON", "labeled-person", { group: 1, priority: 60, confidence: 0.9 });
  addMatches(found, text, /^\s*(?:address|home\s+address|διεύθυνση|διευθυνση)\s*[:=]\s*([^\r\n]{5,200})/gim, "ADDRESS", "labeled-address", { group: 1, priority: 60, confidence: 0.9 });
  addMatches(found, text, /(?<![\w-])S-1-5-21-(?:\d+-){2}\d+(?:-\d+)?(?![\w-])/gi, "SID", "windows-sid", { priority: 82 });
  addMatches(found, text, /(?<![A-F0-9])[A-F0-9]{8}-[A-F0-9]{4}-[1-5][A-F0-9]{3}-[89AB][A-F0-9]{3}-[A-F0-9]{12}(?![A-F0-9])/gi, "GUID", "guid", { priority: 68, normalize: (v) => v.toLowerCase() });
  addMatches(found, text, /(?:host|hostname|computer|workstation)["']?[ \t]*[=:][ \t]*["']?([A-Z0-9_-]{2,63})/gi, "LABELED_HOST", "labeled-host", { group: 1, priority: 67, normalize: (v) => v.toLowerCase() });
  return found;
}

function detectCustom(text, customValues) {
  const found = [];
  customValues.forEach((entry) => {
    const value = String(entry.value ?? "").trim();
    if (value.length < 2) return;
    const type = String(entry.type ?? "CUSTOM").toUpperCase().replace(/[^A-Z0-9_]+/g, "_").replace(/^_|_$/g, "") || "CUSTOM";
    const lowerText = text.toLowerCase();
    const lowerValue = value.toLowerCase();
    let offset = 0;
    while ((offset = lowerText.indexOf(lowerValue, offset)) !== -1) {
      const hit = finding(type, text.slice(offset, offset + value.length), offset, "custom-exact", 1, 99, lowerValue);
      hit.reason = `Engagement-specific ${type} declared in the local scope file.`;
      found.push(hit);
      offset += value.length;
    }
  });
  return found;
}

function resolveOverlaps(findings) {
  const candidates = [...findings].sort((a, b) =>
    b.priority - a.priority || b.confidence - a.confidence || (b.end - b.start) - (a.end - a.start) || a.start - b.start
  );
  const selected = [];
  candidates.forEach((candidate) => {
    if (!selected.some((item) => candidate.start < item.end && item.start < candidate.end)) selected.push(candidate);
  });
  return selected.sort((a, b) => a.start - b.start || a.end - b.end);
}

function enabledForProfile(profile, type) {
  const definition = PROFILE_DEFINITIONS[profile] ?? PROFILE_DEFINITIONS.balanced;
  return definition.types === "all" || definition.types.has(type) || type === "CUSTOM";
}

export function scan(text, options = {}) {
  const profile = options.profile ?? "balanced";
  const region = options.region ?? "global";
  if (!PROFILE_DEFINITIONS[profile]) throw new Error(`Unknown profile: ${profile}`);
  if (!REGION_DEFINITIONS[region]) throw new Error(`Unknown region: ${region}`);
  const allowlist = new Set((options.allowlist ?? []).map((item) => String(item).trim().toLowerCase()).filter(Boolean));
  const findings = detectAll(String(text), profile === "strict")
    .concat(detectCustom(String(text), options.customValues ?? []))
    .filter((item) => enabledForProfile(profile, item.type))
    .filter((item) => !REGIONAL_TYPES[item.type] || REGIONAL_TYPES[item.type].has(region))
    .filter((item) => !allowlist.has(item.value.toLowerCase()));
  return resolveOverlaps(findings);
}

function domainRootIndex(labels) {
  if (labels.length <= 2) return 0;
  const lastTwo = labels.slice(-2).join(".").toLowerCase();
  return COMMON_MULTI_SUFFIXES.has(lastTwo) ? Math.max(0, labels.length - 3) : labels.length - 2;
}

function createPseudonymizer(originalText) {
  const counters = new Map();
  const mappings = new Map();
  const rootDomains = new Map();
  const domainNodes = new Map();
  const ipNetworks = new Map();
  const ipHosts = new Map();

  function next(type) {
    const value = (counters.get(type) ?? 0) + 1;
    counters.set(type, value);
    return value;
  }

  function safePlaceholder(type) {
    let placeholder;
    do {
      placeholder = `{{REDACTED_${type}_${String(next(type)).padStart(3, "0")}}}`;
    } while (originalText.includes(placeholder));
    return placeholder;
  }

  function pseudonymizeDomain(value) {
    const labels = value.toLowerCase().split(".");
    const rootAt = domainRootIndex(labels);
    const root = labels.slice(rootAt).join(".");
    if (!rootDomains.has(root)) rootDomains.set(root, `target-${String(rootDomains.size + 1).padStart(3, "0")}.example`);
    let parentKey = root;
    let output = rootDomains.get(root);
    for (let index = rootAt - 1; index >= 0; index -= 1) {
      const nodeKey = `${labels[index]}.${parentKey}`;
      if (!domainNodes.has(nodeKey)) domainNodes.set(nodeKey, `sub-${String(domainNodes.size + 1).padStart(3, "0")}`);
      output = `${domainNodes.get(nodeKey)}.${output}`;
      parentKey = nodeKey;
    }
    return output;
  }

  function pseudonymizeIp(value, type) {
    if (!value.includes(".")) return safePlaceholder(type);
    const octets = value.split(".");
    const network = octets.slice(0, 3).join(".");
    const networkKey = `${type}:${network}`;
    if (!ipNetworks.has(networkKey)) ipNetworks.set(networkKey, ipNetworks.size + 1);
    if (!ipHosts.has(`${networkKey}:${value}`)) {
      const hostsInNetwork = [...ipHosts.keys()].filter((key) => key.startsWith(`${networkKey}:`)).length + 1;
      ipHosts.set(`${networkKey}:${value}`, hostsInNetwork);
    }
    const scope = type === "PRIVATE_IP" ? "PRIVATE" : "PUBLIC";
    return `{{${scope}_NET_${String(ipNetworks.get(networkKey)).padStart(3, "0")}_HOST_${String(ipHosts.get(`${networkKey}:${value}`)).padStart(3, "0")}}}`;
  }

  return (item) => {
    const key = `${item.type}\u0000${item.normalized}`;
    if (mappings.has(key)) return mappings.get(key);
    let replacement;
    if (item.type === "DOMAIN") {
      replacement = pseudonymizeDomain(item.value);
    } else if (item.type === "EMAIL") {
      const [local, domain] = item.value.split("@");
      const localKey = `EMAIL_LOCAL\u0000${local.toLowerCase()}`;
      if (!mappings.has(localKey)) mappings.set(localKey, `user-${String(next("EMAIL_USER")).padStart(3, "0")}`);
      replacement = `${mappings.get(localKey)}@${pseudonymizeDomain(domain)}`;
    } else if (item.type === "PRIVATE_IP" || item.type === "PUBLIC_IP") {
      replacement = pseudonymizeIp(item.value, item.type);
    } else {
      replacement = safePlaceholder(item.type);
    }
    mappings.set(key, replacement);
    return replacement;
  };
}

export function sanitize(text, options = {}) {
  const input = String(text);
  const mode = options.mode ?? "pseudonymize";
  if (!new Set(["pseudonymize", "redact"]).has(mode)) throw new Error(`Unknown mode: ${mode}`);
  const findings = scan(input, options);
  const pseudonymizer = createPseudonymizer(input);
  const replacements = findings.map((item) => ({
    ...item,
    replacement: mode === "redact" ? `{{REDACTED_${item.type}}}` : pseudonymizer(item),
  }));

  let output = "";
  let cursor = 0;
  const outputReplacementSpans = [];
  replacements.forEach((item) => {
    output += input.slice(cursor, item.start);
    const start = output.length;
    output += item.replacement;
    outputReplacementSpans.push({ start, end: output.length });
    cursor = item.end;
  });
  output += input.slice(cursor);

  const residualFindings = options.verify === false ? [] : scan(output, options).filter((item) =>
    !outputReplacementSpans.some((span) => item.start >= span.start && item.end <= span.end)
  );
  const counts = {};
  replacements.forEach((item) => { counts[item.type] = (counts[item.type] ?? 0) + 1; });

  return {
    sanitizedText: output,
    findings: replacements,
    residualFindings,
    counts,
    safe: residualFindings.length === 0,
  };
}

export function parseScopeFile(source) {
  const parsed = JSON.parse(source);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("The scope must be a JSON object.");
  const rawValues = parsed.sensitive_values ?? parsed.custom_values ?? [];
  if (!Array.isArray(rawValues)) throw new Error("sensitive_values must be an array.");
  const customValues = rawValues.map((entry) => {
    if (typeof entry === "string") return { type: "CUSTOM", value: entry };
    if (!entry || typeof entry !== "object") throw new Error("Invalid sensitive_values entry.");
    return { type: String(entry.type ?? "CUSTOM"), value: String(entry.value ?? "") };
  }).filter((entry) => entry.value.trim().length >= 2);
  const allowlist = Array.isArray(parsed.allowlist) ? parsed.allowlist.map(String) : [];
  const profile = parsed.profile && PROFILE_DEFINITIONS[parsed.profile] ? parsed.profile : null;
  const region = parsed.region && REGION_DEFINITIONS[parsed.region] ? parsed.region : null;
  return { name: String(parsed.engagement ?? parsed.name ?? "Unnamed engagement"), customValues, allowlist, profile, region };
}

export async function readEvidenceFile(file, maxBytes = 10 * 1024 * 1024) {
  if (!file || typeof file.text !== "function") throw new Error("Select a readable evidence file.");
  if (file.size > maxBytes) throw new Error(`Evidence file exceeds the ${Math.floor(maxBytes / 1024 / 1024)} MB limit.`);
  const name = String(file.name ?? "evidence.txt");
  const extension = name.includes(".") ? name.split(".").at(-1).toLowerCase() : "";
  const allowed = new Set(["txt", "log", "json", "xml", "csv", "har", "nessus", "nmap", "md", "yaml", "yml"]);
  if (extension && !allowed.has(extension)) throw new Error(`Unsupported evidence file type: .${extension}`);
  const text = await file.text();
  if (text.includes("\u0000")) throw new Error("Binary evidence files are not supported; export the tool output as text first.");
  return { name, text };
}
