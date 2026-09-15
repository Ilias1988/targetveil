import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const docs = resolve(root, "docs");
const read = (name) => readFile(resolve(docs, name), "utf8");

const [html, privacy, app, engine, demos, worker, manifest, robots, sitemap, googleVerification] = await Promise.all([
  read("index.html"), read("privacy.html"), read("app.js"), read("engine.js"), read("demos.js"), read("service-worker.js"),
  read("manifest.webmanifest"), read("robots.txt"), read("sitemap.xml"), read("google56c60131cae5531b.html"),
]);

const analyticsToken = "6a2fab6683174e5e9deb23e332f374f0";
const analyticsScript = "https://static.cloudflareinsights.com/beacon.min.js";
for (const [name, page] of [["index.html", html], ["privacy.html", privacy]]) {
  assert.match(page, /script-src(?: 'self')? https:\/\/static\.cloudflareinsights\.com\/beacon\.min\.js;/, `${name} CSP must restrict scripts to the analytics beacon`);
  assert.match(page, /connect-src https:\/\/cloudflareinsights\.com;/, `${name} CSP must restrict connections to Cloudflare analytics`);
  assert.equal((page.match(new RegExp(analyticsToken, "g")) ?? []).length, 1, `${name} must contain the current analytics token exactly once`);
  const escapedAnalyticsScript = analyticsScript.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  assert.equal((page.match(new RegExp(`src=["']${escapedAnalyticsScript}["']`, "g")) ?? []).length, 1, `${name} must load the analytics beacon exactly once`);
}
assert.equal((`${html}\n${privacy}`.match(/data-cf-beacon=/g) ?? []).length, 2, "only the two declared analytics integrations are allowed");
assert.match(html, /name="referrer" content="strict-origin"/, "privacy-preserving analytics-compatible referrer policy is missing");
assert.match(privacy, /name="referrer" content="strict-origin"/, "privacy page referrer policy is missing");
assert.match(html, /rel="canonical" href="https:\/\/ilias1988\.github\.io\/targetveil\/"/, "canonical URL is missing");
assert.match(html, /id="about-targetveil"/, "visible SEO description is missing");
assert.match(html, /itemtype="https:\/\/schema\.org\/FAQPage"/, "semantic FAQ markup is missing");
assert.match(html, /https:\/\/github\.com\/Ilias1988/, "creator GitHub link is missing");
assert.match(html, /https:\/\/x\.com\/EliotGeo/, "creator X link is missing");
assert.match(html, /id="evidence-file"/, "local evidence-file control is missing");
assert.match(html, /id="demo-profile"/, "synthetic example selector is missing");
assert.match(html, /Seventeen focused profiles cover web testing/, "homepage profile description is stale");
assert.match(html, /Local evidence workflow/, "homepage local-file capability is missing");
assert.match(html, /Binary files, PDFs, Office documents and images are not processed/, "homepage limitations are not explicit");

const applicationCode = `${app}\n${engine}\n${demos}`;
for (const forbidden of [
  /\bfetch\s*\(/, /XMLHttpRequest/, /sendBeacon/, /new\s+WebSocket/, /localStorage/,
  /sessionStorage/, /indexedDB/, /document\.cookie/,
]) {
  assert.equal(forbidden.test(applicationCode), false, `forbidden browser capability: ${forbidden}`);
}
assert.equal(applicationCode.includes(analyticsToken), false, "analytics token must stay outside sanitizer code");

assert.equal(/source-input|safe-output|custom-values/.test(worker), false, "service worker must not reference prompt fields");
assert.match(worker, /new URL\(event\.request\.url\)\.origin !== self\.location\.origin/, "service worker must be same-origin only");
assert.match(worker, /\.\/demos\.js\?v=1/, "offline cache must include the synthetic demo library");

const localReferences = [...html.matchAll(/(?:src|href)="\.\/([^"#?]+)(?:\?[^"#]*)?"/g)].map((match) => match[1]);
for (const path of localReferences) await stat(resolve(docs, path));

JSON.parse(manifest);
assert.match(robots, /Sitemap: https:\/\/ilias1988\.github\.io\/targetveil\/sitemap\.xml/);
assert.match(sitemap, /https:\/\/ilias1988\.github\.io\/targetveil\//);
assert.equal(googleVerification.trim(), "google-site-verification: google56c60131cae5531b.html", "Google Search Console verification file is invalid");

console.log(`Static privacy verification passed (${new Set(localReferences).size} local assets checked; analytics allowlist verified).`);
