import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function chromeExecutable() {
  const configured = process.env.CHROME_PATH;
  const candidates = configured ? [configured] : process.platform === "win32"
    ? [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
      ]
    : process.platform === "darwin"
      ? ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
      : ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"];
  const executable = candidates.find(existsSync);
  if (!executable) throw new Error("Chrome/Chromium was not found. Set CHROME_PATH to run browser E2E tests.");
  return executable;
}

async function waitFor(check, description, attempts = 100) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const value = await check();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await pause(100);
  }
  throw new Error(`Timed out waiting for ${description}${lastError ? `: ${lastError.message}` : ""}`);
}

async function stopProcess(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill();
  await Promise.race([exited, pause(5000)]);
}

class CdpClient {
  constructor(browserProcess) {
    this.browserProcess = browserProcess;
    this.sequence = 0;
    this.pending = new Map();
    this.listeners = new Map();
    this.sessionId = null;
    this.buffer = "";
    this.browserErrors = "";
    browserProcess.stderr?.setEncoding("utf8");
    browserProcess.stderr?.on("data", (chunk) => { this.browserErrors += chunk; });
    browserProcess.stdio[4].setEncoding("utf8");
    browserProcess.stdio[4].on("data", (chunk) => {
      this.buffer += chunk;
      let boundary;
      while ((boundary = this.buffer.indexOf("\u0000")) !== -1) {
        const raw = this.buffer.slice(0, boundary);
        this.buffer = this.buffer.slice(boundary + 1);
        if (raw) this.handleMessage(JSON.parse(raw));
      }
    });
    browserProcess.once("exit", (code) => {
      const detail = this.browserErrors.trim().split(/\r?\n/).slice(-3).join(" | ");
      for (const pending of this.pending.values()) {
        pending.reject(new Error(`Chrome exited (${code}) before completing a command${detail ? `: ${detail}` : ""}`));
      }
      this.pending.clear();
    });
  }

  async open() {
    await pause(100);
  }

  handleMessage(message) {
    if (message.id && this.pending.has(message.id)) {
      const { resolve, reject } = this.pending.get(message.id);
      this.pending.delete(message.id);
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result);
    }
    const callbacks = this.listeners.get(message.method) ?? [];
    callbacks.forEach((callback) => callback(message.params));
    this.listeners.delete(message.method);
  }

  send(method, params = {}, sessionId = this.sessionId, timeout = 30000) {
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Timed out running Chrome command ${method}`));
      }, timeout);
      this.pending.set(id, {
        resolve: (value) => { clearTimeout(timer); resolve(value); },
        reject: (error) => { clearTimeout(timer); reject(error); },
      });
      const message = { id, method, params };
      if (sessionId) message.sessionId = sessionId;
      this.browserProcess.stdio[3].write(`${JSON.stringify(message)}\u0000`);
    });
  }

  event(method, timeout = 15000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${method}`)), timeout);
      const callback = (params) => {
        clearTimeout(timer);
        resolve(params);
      };
      this.listeners.set(method, [...(this.listeners.get(method) ?? []), callback]);
    });
  }

  async evaluate(expression) {
    const response = await this.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (response.exceptionDetails) throw new Error(response.exceptionDetails.text);
    return response.result.value;
  }

  close() {
    this.browserProcess.stdio[3].end();
  }
}

const port = await freePort();
const profileDirectory = await mkdtemp(join(tmpdir(), "targetveil-e2e-"));
const python = process.platform === "win32" ? "python" : "python3";
const server = spawn(python, ["-m", "http.server", String(port), "--directory", "docs", "--bind", "127.0.0.1"], {
  cwd: root,
  stdio: "ignore",
});
let browser;
let client;

try {
  console.log("E2E: starting local server");
  await waitFor(async () => (await fetch(`http://127.0.0.1:${port}/`, { cache: "no-store" })).ok, "local HTTP server");
  console.log("E2E: launching clean browser");
  browser = spawn(chromeExecutable(), [
    "--headless=new",
    "--remote-debugging-pipe",
    `--user-data-dir=${profileDirectory}`,
    "--no-first-run",
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-gpu",
    "--disable-software-rasterizer",
    "--disable-dev-shm-usage",
    "--no-sandbox",
    "about:blank",
  ], { stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"] });
  console.log("E2E: connecting to DevTools");
  client = new CdpClient(browser);
  await client.open();
  const { targetId } = await client.send("Target.createTarget", { url: "about:blank" }, null);
  const { sessionId } = await client.send("Target.attachToTarget", { targetId, flatten: true }, null);
  client.sessionId = sessionId;
  console.log("E2E: DevTools pipe ready");
  await client.send("Page.enable");
  await client.send("Runtime.enable");
  const loaded = client.event("Page.loadEventFired");
  await client.send("Page.navigate", { url: `http://127.0.0.1:${port}/` });
  await loaded;
  console.log("E2E: exercising all profile demos");

  const demoResults = await client.evaluate(`(async () => {
    const wait = () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    const demoSelect = document.querySelector("#demo-profile");
    const results = [];
    for (const option of [...demoSelect.options]) {
      demoSelect.value = option.value;
      document.querySelector("#demo-button").click();
      document.querySelector("#sanitize-button").click();
      await wait();
      results.push({
        profile: option.value,
        rows: document.querySelectorAll("#findings-body tr").length,
        safe: document.querySelector("#status-badge").textContent.includes("passed"),
        copyEnabled: !document.querySelector("#copy-button").disabled,
        downloadEnabled: !document.querySelector("#download-button").disabled,
      });
    }
    return {
      profiles: document.querySelectorAll("#profile option").length,
      demos: demoSelect.options.length,
      results,
    };
  })()`);
  assert.equal(demoResults.profiles, 17);
  assert.equal(demoResults.demos, 17);
  for (const result of demoResults.results) {
    assert.ok(result.rows > 0, `${result.profile} UI demo has no findings`);
    assert.ok(result.safe, `${result.profile} UI demo did not verify`);
    assert.ok(result.copyEnabled && result.downloadEnabled, `${result.profile} result actions are disabled`);
  }

  console.log("E2E: exercising local evidence and scope files");

  const fileFlow = await client.evaluate(`(async () => {
    const evidence = new DataTransfer();
    evidence.items.add(new File(["host=files.synthetic-client.net source=10.91.8.7 password=FileCanary-778"], "scanner.log", { type: "text/plain" }));
    const evidenceInput = document.querySelector("#evidence-file");
    evidenceInput.files = evidence.files;
    evidenceInput.dispatchEvent(new Event("change", { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 100));

    const scope = new DataTransfer();
    scope.items.add(new File([JSON.stringify({
      engagement: "E2E Synthetic",
      profile: "siem",
      sensitive_values: [{ type: "CASE_ID", value: "CASE-CANARY-991" }],
      allowlist: ["example.com"],
    })], "scope.json", { type: "application/json" }));
    const scopeInput = document.querySelector("#scope-file");
    scopeInput.files = scope.files;
    scopeInput.dispatchEvent(new Event("change", { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 100));

    document.querySelector("#source-input").value += " case=CASE-CANARY-991";
    document.querySelector("#sanitize-button").click();
    const output = document.querySelector("#safe-output").value;
    const loaded = document.querySelector("#evidence-status").textContent.includes("scanner.log")
      && document.querySelector("#scope-status").textContent.includes("E2E Synthetic");
    document.querySelector("#clear-button").click();
    return {
      loaded,
      noLeak: !output.includes("files.synthetic-client.net") && !output.includes("10.91.8.7")
        && !output.includes("FileCanary-778") && !output.includes("CASE-CANARY-991"),
      cleared: document.querySelector("#source-input").value === "" && document.querySelector("#result-panel").hidden,
    };
  })()`);
  assert.deepEqual(fileFlow, { loaded: true, noLeak: true, cleared: true });

  console.log("E2E: checking responsive layout and outbound resources");
  const responsive = await client.evaluate(`({
    noHorizontalOverflow: document.documentElement.scrollWidth <= document.documentElement.clientWidth,
    title: document.title,
    outboundResources: performance.getEntriesByType("resource")
      .map((entry) => new URL(entry.name).origin)
      .filter((origin) => origin !== location.origin),
  })`);
  assert.equal(responsive.noHorizontalOverflow, true);
  assert.match(responsive.title, /TargetVeil/);
  const permittedOutboundOrigins = new Set([
    "https://static.cloudflareinsights.com",
    "https://cloudflareinsights.com",
  ]);
  assert.equal(
    responsive.outboundResources.every((origin) => permittedOutboundOrigins.has(origin)),
    true,
    `unexpected outbound resource: ${responsive.outboundResources.join(", ")}`,
  );
  const accessibility = await client.evaluate(`({
    unnamedButtons: [...document.querySelectorAll("button")].filter((item) => !item.textContent.trim() && !item.getAttribute("aria-label")).length,
    unlabelledInputs: [...document.querySelectorAll("input, select, textarea")].filter((item) => !item.labels?.length && !item.getAttribute("aria-label")).length,
    hasMain: Boolean(document.querySelector("main")),
    hasH1: document.querySelectorAll("h1").length === 1,
  })`);
  assert.deepEqual(accessibility, { unnamedButtons: 0, unlabelledInputs: 0, hasMain: true, hasH1: true });

  await client.send("Emulation.setDeviceMetricsOverride", {
    width: 390,
    height: 844,
    deviceScaleFactor: 1,
    mobile: true,
  });
  const mobileLayout = await client.evaluate(`({
    noHorizontalOverflow: document.documentElement.scrollWidth <= document.documentElement.clientWidth,
    demoControlsVisible: document.querySelector(".demo-controls").getBoundingClientRect().width > 0,
    viewportWidth: document.documentElement.clientWidth,
  })`);
  assert.deepEqual(mobileLayout, { noHorizontalOverflow: true, demoControlsVisible: true, viewportWidth: 390 });
  await client.send("Emulation.clearDeviceMetricsOverride");

  console.log("E2E: checking service worker and offline reload");
  const serviceWorkerReady = await client.evaluate(`(async () => {
    if (!("serviceWorker" in navigator)) return false;
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await Promise.race([
        new Promise((resolve) => navigator.serviceWorker.addEventListener("controllerchange", resolve, { once: true })),
        new Promise((resolve) => setTimeout(resolve, 5000)),
      ]);
    }
    return Boolean(navigator.serviceWorker.controller);
  })()`);
  assert.equal(serviceWorkerReady, true);

  await stopProcess(server);
  const offlineLoaded = client.event("Page.loadEventFired");
  await client.send("Page.reload");
  await offlineLoaded;
  const offlineState = await client.evaluate(`({
    brand: document.querySelector(".brand")?.textContent.replace(/\\s+/g, " ").trim(),
    demoCount: document.querySelectorAll("#demo-profile option").length,
  })`);
  assert.equal(offlineState.brand, "TV TargetVeil");
  assert.equal(offlineState.demoCount, 17);

  console.log(`Browser E2E passed (${demoResults.demos} demos, file/scope flow, privacy, responsive and offline reload).`);
} finally {
  client?.close();
  await stopProcess(server);
  await stopProcess(browser);
  await rm(profileDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
