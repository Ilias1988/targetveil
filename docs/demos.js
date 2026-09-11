/**
 * Synthetic, non-production examples for every TargetVeil profile.
 * Values are fictional and exist only to demonstrate local detection.
 */

export const DEMO_DEFINITIONS = Object.freeze({
  balanced: {
    label: "Balanced assessment notes",
    profile: "balanced",
    canaries: ["ada.canary@northstar-labs.test", "10.24.8.17"],
    text: `Client contact: Ada Canary
Email: ada.canary@northstar-labs.test
Internal API: https://api.northstar-labs.test/v2
Source: 10.24.8.17`,
  },
  burp: {
    label: "Burp / raw HTTP request",
    profile: "burp",
    canaries: ["portal.acme-pentest.gr", "SyntheticPass!2026", "10.20.30.41"],
    text: `POST /api/v1/users/42 HTTP/1.1
Host: portal.acme-pentest.gr
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.c3ludGhldGljLXVzZXI.c3ludGhldGljLXNpZw
Cookie: session=synthetic-session-7f9a; csrftoken=demo-123
Content-Type: application/json

{"username":"analyst@acme-pentest.gr","password":"SyntheticPass!2026","callback":"https://api.acme-pentest.gr/hook","source_ip":"10.20.30.41"}`,
  },
  nmap: {
    label: "Nmap service discovery",
    profile: "nmap",
    canaries: ["dc01.synthetic-corp.internal", "10.55.2.10", "02:42:AC:11:00:02"],
    text: `Nmap scan report for dc01.synthetic-corp.internal (10.55.2.10)
Host is up (0.0012s latency).
MAC Address: 02:42:AC:11:00:02
443/tcp open https`,
  },
  nuclei: {
    label: "Nuclei authenticated finding",
    profile: "nuclei",
    canaries: ["admin.synthetic-target.net", "203.0.113.88"],
    text: `[critical] [exposed-panel] https://admin.synthetic-target.net/login
Authorization: Bearer eyJ0eXAiOiJKV1QifQ.c3ludGhldGljLXVzZXI.c2lnbmF0dXJl
matched-at: 203.0.113.88`,
  },
  ffuf: {
    label: "ffuf content discovery",
    profile: "ffuf",
    canaries: ["staging.synthetic-target.org", "10.60.4.22"],
    text: `:: URL : https://staging.synthetic-target.org/FUZZ
:: Header : Cookie: session=ffuf-canary-77881
admin [Status: 200, Size: 4312]
Source IP: 10.60.4.22`,
  },
  bloodhound: {
    label: "BloodHound / Active Directory",
    profile: "bloodhound",
    canaries: ["SYNTHETIC\\svc_graph", "S-1-5-21-111111111-222222222-333333333-1105"],
    text: `Principal: SYNTHETIC\\svc_graph
Domain: lab.synthetic-corp.local
computer=DC-SYNTH-01
ObjectSid: S-1-5-21-111111111-222222222-333333333-1105
ObjectId: 6ba7b810-9dad-11d1-80b4-00c04fd430c8`,
  },
  siem: {
    label: "SIEM authentication event",
    profile: "siem",
    canaries: ["10.70.2.44", "analyst@synthetic-enterprise.net", "siem-canary-session-4419"],
    text: `2026-09-11T12:03:18Z event=login_failed source_ip=10.70.2.44
host=auth.synthetic-enterprise.net username=analyst@synthetic-enterprise.net
session_id=siem-canary-session-4419`,
  },
  sqlmap: {
    label: "sqlmap / database access",
    profile: "sqlmap",
    canaries: ["db_canary", "SqlDemoPass-881", "db.synthetic-shop.net", "10.88.1.14"],
    text: `sqlmap identified the back-end DBMS as PostgreSQL
connection=postgresql://db_canary:SqlDemoPass-881@db.synthetic-shop.net:5432/customers
web server: 10.88.1.14`,
  },
  web_discovery: {
    label: "Gobuster / Nikto / WPScan",
    profile: "web_discovery",
    canaries: ["cms.synthetic-media.org", "198.51.100.42", "sk-demoSyntheticKey123456789012345"],
    text: `Target: https://cms.synthetic-media.org
/wp-admin (Status: 302)
Nikto host IP: 198.51.100.42
api_key=sk-demoSyntheticKey123456789012345`,
  },
  netexec: {
    label: "NetExec / Impacket SMB",
    profile: "netexec",
    canaries: ["10.50.2.14", "SYNTHETIC\\svc_backup", "8846f7eaee8fb117ad06bdd830b7586c"],
    text: `SMB 10.50.2.14 445 DC-SYNTH-01 [+] SYNTHETIC\\svc_backup
Username : svc_backup
NTLM : 8846f7eaee8fb117ad06bdd830b7586c
Domain: ad.synthetic-lab.local`,
  },
  mimikatz: {
    label: "Mimikatz credential material",
    profile: "mimikatz",
    canaries: ["lab_operator", "auth.synthetic-domain.local", "32ed87bdb5fdc5e9cba88547376818d4"],
    text: `Authentication Id : 0 ; 441992
User Name : lab_operator
Domain : auth.synthetic-domain.local
NTLM : 32ed87bdb5fdc5e9cba88547376818d4`,
  },
  metasploit: {
    label: "Metasploit session output",
    profile: "metasploit",
    canaries: ["10.90.1.5", "198.51.100.70", "MeterpreterDemo-771"],
    text: `[*] Meterpreter session opened (10.90.1.5:4444 -> 198.51.100.70:51922)
host=workstation.synthetic-client.net
username=operator@synthetic-client.net
password=MeterpreterDemo-771`,
  },
  wireshark: {
    label: "Wireshark / tcpdump packet text",
    profile: "wireshark",
    canaries: ["02:42:ac:11:00:02", "fd00:42::19", "api.synthetic-network.net"],
    text: `Ethernet II, Src: 02:42:ac:11:00:02, Dst: 02:42:ac:11:00:03
Internet Protocol, Src: fd00:42::19, Dst: 2001:db8:85a3::8a2e:370:7334
DNS query: api.synthetic-network.net`,
  },
  vuln_scanner: {
    label: "Nessus / OpenVAS finding",
    profile: "vuln_scanner",
    canaries: ["vpn.synthetic-client.org", "203.0.113.99", "NessusDemo-335"],
    text: `Host: vpn.synthetic-client.org (203.0.113.99)
Plugin: 15901 SSL Certificate Information
Credentialed user: scanner@synthetic-client.org
password=NessusDemo-335`,
  },
  cloud: {
    label: "AWS / Azure / GCP / Kubernetes",
    profile: "cloud",
    canaries: ["123456789012", "private-prod-77881", "AKIAIOSFODNN7EXAMPLE"],
    text: `AWS account ID: 123456789012
role=arn:aws:iam::123456789012:role/SyntheticAuditRole
tenant_id=6ba7b810-9dad-11d1-80b4-00c04fd430c8
project_id=private-prod-77881
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
token: ZXlKaGJHY2lPaUpTVXpJMU5pSjkuY2FuYXJ5`,
  },
  osint: {
    label: "OSINT / reconnaissance notes",
    profile: "osint",
    canaries: ["Alice Synthetic", "alice.synthetic@research-target.net", "+44 20 7946 0958"],
    text: `Full name: Alice Synthetic
Email: alice.synthetic@research-target.net
Phone: +44 20 7946 0958
Address: 10 Canary Street, Example City
Portal: people.research-target.net`,
  },
  strict: {
    label: "Strict mixed-data review",
    profile: "strict",
    canaries: ["Strict Canary", "strict.canary@private-target.net", "123-45-6789"],
    text: `Full name: Strict Canary
Email: strict.canary@private-target.net
SSN: 123-45-6789
IBAN: GR6700000000000000000000000
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.c3RyaWN0LWNhbmFyeQ.c2lnbmF0dXJl
password=StrictDemo-991
target=127.0.0.1`,
  },
});
