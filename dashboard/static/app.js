const $ = (id) => document.getElementById(id);
let activeTaskId = null;
let pollHandle = null;
let providerDefaults = {};

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || "Request failed");
  return payload;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
}

function optionList(select, entries, selected) {
  select.innerHTML = entries.map((entry) => `<option value="${escapeHtml(entry.path)}" ${entry.path === selected ? "selected" : ""}>${escapeHtml(entry.path)} · ${entry.count}</option>`).join("");
}

async function loadCatalog() {
  const data = await api("/api/catalog");
  optionList($("interfacePath"), data.interface_files, "code/result/Tenda/AC/AC18/AC18_page.json");
  optionList($("databasePath"), data.database_files, data.default_database);
  $("metricInterfaces").textContent = "0";
}

function updateInterfaceSource() {
  const source = $("interfaceSource").value;
  const captured = ["har-json", "offline-json"].includes(source);
  $("offlineInterfaceField").hidden = !captured;
  $("interfaceFileField").hidden = source !== "har-json";
}

async function loadProviders() {
  providerDefaults = await api("/api/providers");
  updateProviderFields();
}

function updateProviderFields() {
  const provider = $("provider").value;
  const defaults = providerDefaults[provider] || {};
  if (defaults.model) $("model").value = defaults.model;
  if (defaults.base_url) $("baseUrl").value = defaults.base_url;
  const status = $("providerStatus");
  status.textContent = defaults.configured ? "本机已配置" : "未测试";
  status.className = `provider-status ${defaults.configured ? "configured" : ""}`;
}

async function configFromForm() {
  const source = $("interfaceSource").value;
  const config = {
    target_url: $("targetUrl").value.trim(), username: $("username").value, password: $("password").value,
    login_path: $("loginPath").value.trim(), username_field: $("usernameField").value.trim() || "username",
    password_field: $("passwordField").value.trim() || "password", method: $("method").value,
    interface_source: source,
    interface_path: ["har-json", "offline-json"].includes(source) ? $("interfacePath").value : "",
    database_path: $("databasePath").value,
    max_pages: Number($("maxPages").value), max_depth: Number($("maxDepth").value),
    threshold: Number($("threshold").value), max_cases: Number($("maxCases").value),
    delay_ms: Number($("delayMs").value), timeout: Number($("timeout").value),
    mode: document.querySelector('input[name="mode"]:checked').value, authorized: $("authorized").checked,
    llm_enabled: $("llmEnabled").checked, provider: $("provider").value,
    model: $("model").value.trim(), base_url: $("baseUrl").value.trim(), api_key: $("apiKey").value
  };
  if (source === "har-json") {
    const file = $("interfaceFile").files[0];
    if (file) {
      try { config.interface_json = JSON.parse(await file.text()); }
      catch (error) { throw new Error(`HAR 文件不是有效 JSON: ${error.message}`); }
      config.interface_path = "";
    }
  }
  return config;
}

async function startTask(event) {
  event.preventDefault();
  try {
    const task = await api("/api/tasks", { method: "POST", body: JSON.stringify(await configFromForm()) });
    activeTaskId = task.id;
    $("stopButton").disabled = false;
    $("emptyState").hidden = true;
    $("resultContent").hidden = false;
    startPolling();
  } catch (error) { alert(error.message); }
}

function startPolling() {
  if (pollHandle) clearInterval(pollHandle);
  pollTask();
  pollHandle = setInterval(pollTask, 1000);
}

async function pollTask() {
  if (!activeTaskId) return;
  try {
    const task = await api(`/api/tasks/${activeTaskId}/results`);
    renderTask(task.task, task.results || []);
    if (["completed", "failed", "stopped"].includes(task.task.status)) {
      clearInterval(pollHandle); pollHandle = null; $("stopButton").disabled = true;
    }
  } catch (error) { console.error(error); }
}

function renderTask(task, results) {
  $("currentTask").textContent = task.id;
  $("currentPhase").textContent = `${task.status} · ${task.phase || ""}`;
  $("metricMatches").textContent = task.matches || 0;
  $("metricInterfaces").textContent = task.discovered_interfaces || 0;
  $("metricCases").textContent = task.total || 0;
  $("metricAnomalies").textContent = task.anomalies || 0;
  const percent = task.total ? Math.min(100, Math.round((task.processed || 0) / task.total * 100)) : 0;
  $("progressLabel").textContent = `${task.processed || 0} / ${task.total || 0}`;
  $("progressPhase").textContent = task.phase || task.status;
  $("progressBar").style.width = `${percent}%`;
  renderMatches(task); renderCases(results); renderLogs(task.logs || []);
}

function renderMatches(task) {
  const matches = task.matches_detail || [];
  if (!matches.length) { $("matchesTab").innerHTML = `<p class="muted">任务正在准备匹配结果。</p>`; return; }
  $("matchesTab").innerHTML = matches.map((item) => {
    const iface = item.interface || {}; const top = (item.matches || [])[0];
    return `<div class="result-row"><div class="score">${item.match_count || 0}<small>hits</small></div><div><div class="uri">${escapeHtml(iface.URI || "/")}</div><small>${escapeHtml(iface.navigation || "")}</small></div><div class="score">${top ? top.score : 0}<small>score</small></div></div>`;
  }).join("");
}

function renderCases(results) {
  const cases = results.filter((item) => item.kind !== "login");
  $("casesTab").innerHTML = cases.length ? cases.map((item) => `<div class="result-row"><div><span class="pill ${item.anomaly ? "alert" : ""}">${escapeHtml(item.status || "preview")}</span></div><div><div class="uri">${escapeHtml(item.method || "")} ${escapeHtml(item.uri || "")}</div><small>parameter: <span class="code">${escapeHtml(item.parameter || "")}</span> · value: <span class="code">${escapeHtml(item.value || "")}</span></small></div><div class="score">${item.status && typeof item.status === "number" ? item.status : "-"}<small>${item.elapsed_ms ? `${item.elapsed_ms} ms` : "not sent"}</small></div></div>`).join("") : `<p class="muted">暂无测试用例。</p>`;
}

function renderLogs(logs) { $("logsTab").innerHTML = logs.length ? logs.map((log) => `<div class="log-line"><time>${escapeHtml(log.time)}</time><span>${escapeHtml(log.message)}</span></div>`).join("") : `<p class="muted">暂无日志。</p>`; }
async function stopTask() { if (activeTaskId) await api(`/api/tasks/${activeTaskId}/stop`, { method: "POST", body: "{}" }); }
async function testApi() {
  const status = $("providerStatus");
  status.textContent = "测试中..."; status.className = "provider-status testing";
  try {
    const result = await api("/api/providers/test", { method: "POST", body: JSON.stringify({
      provider: $("provider").value, model: $("model").value.trim(), base_url: $("baseUrl").value.trim(),
      api_key: $("apiKey").value, timeout: Number($("timeout").value) || 20
    })});
    status.textContent = `连接成功 ${result.status}`; status.className = "provider-status ok";
  } catch (error) { status.textContent = error.message || "连接失败"; status.className = "provider-status bad"; }
}
async function buildCveDatabase() {
  const status = $("cveStatus");
  status.textContent = "搜索中..."; status.className = "provider-status testing";
  try {
    const result = await api("/api/cve/search", { method: "POST", body: JSON.stringify({
      vendor: $("cveVendor").value.trim(), product: $("cveProduct").value.trim(),
      version: $("cveVersion").value.trim(), keywords: $("cveKeywords").value.trim(),
      provider: $("provider").value, model: $("model").value.trim(), base_url: $("baseUrl").value.trim(), api_key: $("apiKey").value
    })});
    await loadCatalog(); $("databasePath").value = result.path;
    status.textContent = `已生成 ${result.cve_count} 条`;
    status.className = "provider-status ok";
  } catch (error) { status.textContent = error.message || "生成失败"; status.className = "provider-status bad"; }
}
function bindTabs() { document.querySelectorAll(".tab").forEach((button) => button.addEventListener("click", () => { document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active")); document.querySelectorAll(".tab-content").forEach((item) => item.hidden = true); button.classList.add("active"); $(`${button.dataset.tab}Tab`).hidden = false; })); }

async function init() {
  try { await api("/api/health"); $("healthText").textContent = "service ready"; await loadCatalog(); await loadProviders(); }
  catch (error) { $("healthText").textContent = "service unavailable"; console.error(error); }
  $("provider").addEventListener("change", updateProviderFields); $("testApiButton").addEventListener("click", testApi); $("buildCveButton").addEventListener("click", buildCveDatabase); $("interfaceSource").addEventListener("change", updateInterfaceSource); updateInterfaceSource();
  $("taskForm").addEventListener("submit", startTask); $("stopButton").addEventListener("click", stopTask); $("refreshButton").addEventListener("click", pollTask); bindTabs();
}
init();
