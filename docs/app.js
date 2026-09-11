import { PROFILE_DEFINITIONS, REGION_DEFINITIONS, parseScopeFile, readEvidenceFile, sanitize } from "./engine.js?v=3";
import { DEMO_DEFINITIONS } from "./demos.js?v=1";

const input = document.querySelector("#source-input");
const output = document.querySelector("#safe-output");
const profile = document.querySelector("#profile");
const mode = document.querySelector("#mode");
const region = document.querySelector("#region");
const customValues = document.querySelector("#custom-values");
const allowlist = document.querySelector("#allowlist");
const sanitizeButton = document.querySelector("#sanitize-button");
const copyButton = document.querySelector("#copy-button");
const downloadButton = document.querySelector("#download-button");
const clearButton = document.querySelector("#clear-button");
const evidenceInput = document.querySelector("#evidence-file");
const evidenceStatus = document.querySelector("#evidence-status");
const scopeInput = document.querySelector("#scope-file");
const scopeStatus = document.querySelector("#scope-status");
const findingsBody = document.querySelector("#findings-body");
const resultPanel = document.querySelector("#result-panel");
const statusBadge = document.querySelector("#status-badge");
const summary = document.querySelector("#summary");
const profileHelp = document.querySelector("#profile-help");
const demoProfile = document.querySelector("#demo-profile");

let loadedScope = { name: null, customValues: [], allowlist: [], profile: null, region: null };
let evidenceName = "targetveil-output.txt";

const profileGroups = new Map();
Object.entries(PROFILE_DEFINITIONS).forEach(([value, definition]) => {
  const groupName = definition.group ?? "Other";
  if (!profileGroups.has(groupName)) {
    const optgroup = document.createElement("optgroup");
    optgroup.label = groupName;
    profileGroups.set(groupName, optgroup);
    profile.append(optgroup);
  }
  const option = document.createElement("option");
  option.value = value;
  option.textContent = definition.label;
  profileGroups.get(groupName).append(option);
});
profile.value = "burp";
const demoGroups = new Map();
Object.entries(DEMO_DEFINITIONS).forEach(([value, demo]) => {
  const groupName = PROFILE_DEFINITIONS[demo.profile]?.group ?? "Other";
  if (!demoGroups.has(groupName)) {
    const optgroup = document.createElement("optgroup");
    optgroup.label = groupName;
    demoGroups.set(groupName, optgroup);
    demoProfile.append(optgroup);
  }
  const option = document.createElement("option");
  option.value = value;
  option.textContent = demo.label;
  demoGroups.get(groupName).append(option);
});
demoProfile.value = "burp";
Object.entries(REGION_DEFINITIONS).forEach(([value, label]) => {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = label;
  region.append(option);
});
region.value = "global";

function updateProfileHelp() {
  profileHelp.textContent = PROFILE_DEFINITIONS[profile.value].description;
}
profile.addEventListener("change", updateProfileHelp);
updateProfileHelp();

function parseLines(value, defaultType = "CUSTOM") {
  return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
    const separator = line.indexOf("=");
    return separator > 0
      ? { type: line.slice(0, separator).trim(), value: line.slice(separator + 1).trim() }
      : { type: defaultType, value: line };
  });
}

function renderFindings(result) {
  findingsBody.replaceChildren();
  result.findings.forEach((item) => {
    const row = document.createElement("tr");
    const typeCell = document.createElement("td");
    const valueCell = document.createElement("td");
    const replacementCell = document.createElement("td");
    const detectorCell = document.createElement("td");
    const reasonCell = document.createElement("td");
    const tag = document.createElement("span");
    tag.className = "entity-tag";
    tag.textContent = item.type;
    typeCell.append(tag);
    valueCell.textContent = item.value;
    replacementCell.textContent = item.replacement;
    detectorCell.textContent = `${item.detector} · ${Math.round(item.confidence * 100)}%`;
    reasonCell.textContent = item.reason;
    row.append(typeCell, valueCell, replacementCell, detectorCell, reasonCell);
    findingsBody.append(row);
  });
}

function runSanitizer() {
  const text = input.value;
  if (!text.trim()) {
    input.focus();
    return;
  }
  const manual = parseLines(customValues.value);
  const manualAllowlist = parseLines(allowlist.value).map((entry) => entry.value);
  const result = sanitize(text, {
    profile: profile.value,
    mode: mode.value,
    region: region.value,
    customValues: [...loadedScope.customValues, ...manual],
    allowlist: [...loadedScope.allowlist, ...manualAllowlist],
  });
  output.value = result.sanitizedText;
  renderFindings(result);
  resultPanel.hidden = false;
  copyButton.disabled = !result.safe;
  downloadButton.disabled = !result.safe;
  statusBadge.className = result.safe ? "status safe" : "status warning";
  statusBadge.textContent = result.safe ? "Local verification passed" : "Review residual findings";
  const count = result.findings.length;
  const kinds = Object.entries(result.counts).map(([kind, amount]) => `${kind}: ${amount}`).join(" · ");
  summary.textContent = count
    ? `${count} replacements — ${kinds}`
    : "No sensitive values were detected. Perform a manual review before use.";
  resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

sanitizeButton.addEventListener("click", runSanitizer);

copyButton.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(output.value);
    copyButton.textContent = "Copied";
    setTimeout(() => { copyButton.textContent = "Copy sanitized prompt"; }, 1600);
  } catch {
    output.select();
    document.execCommand("copy");
  }
});

downloadButton.addEventListener("click", () => {
  if (downloadButton.disabled) return;
  const blob = new Blob([output.value], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  const base = evidenceName.replace(/\.[^.]+$/, "").replace(/[^A-Za-z0-9._-]+/g, "-") || "evidence";
  anchor.href = url;
  anchor.download = `${base}.sanitized.txt`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
});

clearButton.addEventListener("click", () => {
  input.value = "";
  output.value = "";
  customValues.value = "";
  allowlist.value = "";
  loadedScope = { name: null, customValues: [], allowlist: [], profile: null, region: null };
  evidenceName = "targetveil-output.txt";
  evidenceInput.value = "";
  evidenceStatus.textContent = "Text exports up to 10 MB · processed only in this tab.";
  scopeInput.value = "";
  scopeStatus.textContent = "No scope file loaded.";
  findingsBody.replaceChildren();
  resultPanel.hidden = true;
  copyButton.disabled = true;
  downloadButton.disabled = true;
  input.focus();
});

evidenceInput.addEventListener("change", async () => {
  const file = evidenceInput.files?.[0];
  if (!file) return;
  try {
    const evidence = await readEvidenceFile(file);
    evidenceName = evidence.name;
    input.value = evidence.text;
    evidenceStatus.textContent = `${evidence.name}: ${(file.size / 1024).toFixed(1)} KB loaded in browser memory.`;
    resultPanel.hidden = true;
    copyButton.disabled = true;
    downloadButton.disabled = true;
    input.focus();
  } catch (error) {
    evidenceInput.value = "";
    evidenceStatus.textContent = `Could not load evidence: ${error.message}`;
  }
});

scopeInput.addEventListener("change", async () => {
  const file = scopeInput.files?.[0];
  if (!file) return;
  if (file.size > 1024 * 1024) {
    scopeStatus.textContent = "The scope file exceeds the 1 MB limit.";
    return;
  }
  try {
    loadedScope = parseScopeFile(await file.text());
    if (loadedScope.profile) {
      profile.value = loadedScope.profile;
      updateProfileHelp();
    }
    if (loadedScope.region) region.value = loadedScope.region;
    scopeStatus.textContent = `${loadedScope.name}: ${loadedScope.customValues.length} sensitive values, ${loadedScope.allowlist.length} allowlisted.`;
  } catch (error) {
    loadedScope = { name: null, customValues: [], allowlist: [], profile: null, region: null };
    scopeStatus.textContent = `Could not load scope: ${error.message}`;
  }
});

document.querySelector("#demo-button").addEventListener("click", () => {
  const demo = DEMO_DEFINITIONS[demoProfile.value];
  input.value = demo.text;
  customValues.value = "";
  profile.value = demo.profile;
  evidenceName = `${demo.profile}-synthetic-demo.txt`;
  evidenceInput.value = "";
  evidenceStatus.textContent = `${demo.label}: synthetic example loaded in browser memory.`;
  resultPanel.hidden = true;
  copyButton.disabled = true;
  downloadButton.disabled = true;
  updateProfileHelp();
  input.focus();
});

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => navigator.serviceWorker.register("./service-worker.js").catch(() => {}));
}
