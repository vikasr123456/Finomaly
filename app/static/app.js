/* Analyst console front end (financial intelligence platform).
 *
 * Rendering rule enforced throughout: model-generated prose and every upstream
 * string are inserted with textContent / createTextNode only. No HTML-string
 * sink is used, so Qwen output cannot execute as markup or script even if it
 * contains HTML-like or instruction-like text. This complements the server CSP,
 * which already forbids inline script.
 */
"use strict";

const state = {
  alerts: [], overview: null, forecast: null, invoices: [], expenses: [],
  sortKey: "created_at", sortDir: -1, selected: null, timer: null,
  activeTab: "overview",
};

const $ = (id) => document.getElementById(id);

function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = String(value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else if (value !== null && value !== undefined) node.setAttribute(key, String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    node.appendChild(typeof child === "object" ? child : document.createTextNode(String(child)));
  }
  return node;
}

function svg(tag, props) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(props || {})) node.setAttribute(key, String(value));
  return node;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

const money = (minor, currency) => {
  try {
    return new Intl.NumberFormat(undefined, { style: "currency", currency: currency || "USD" })
      .format((Number(minor) || 0) / 100);
  } catch (_) { return `${(Number(minor) || 0) / 100} ${currency || ""}`.trim(); }
};
const num = (value, digits = 4) =>
  (typeof value === "number" && Number.isFinite(value)) ? value.toFixed(digits) : String(value);
const cents = (value) =>
  (typeof value === "number" && Number.isFinite(value)) ? (value / 100).toLocaleString(undefined, { maximumFractionDigits: 0 }) + " USD" : "—";
const badge = (text, kind) => el("span", { class: `badge ${kind || text}`, text });

async function api(path, options) {
  const response = await fetch(path, options);
  if (response.status === 401) { showLogin(); throw new Error("unauthenticated"); }
  if (!response.ok) {
    let detail = `http_${response.status}`;
    try { detail = (await response.json()).error || detail; } catch (_) { /* keep status */ }
    throw new Error(detail);
  }
  return response.json();
}

const CSRF = { "X-Requested-With": "dashboard" };

function showLogin(message) {
  stopPolling();
  $("console").hidden = true;
  $("drawer").hidden = true;
  $("login").hidden = false;
  const box = $("login-error");
  box.hidden = !message;
  box.textContent = message || "";
}

function showConsole() {
  $("login").hidden = true;
  $("console").hidden = false;
  startPolling();
  loadAll();
}

async function signIn() {
  const token = $("token").value;
  try {
    const response = await fetch("/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    if (!response.ok) throw new Error("invalid_token");
    $("token").value = "";
    showConsole();
  } catch (error) {
    showLogin("Sign-in failed. Check the dashboard token, and that DASHBOARD_TOKEN is configured server-side.");
  }
}

async function signOut() {
  try { await fetch("/session/logout", { method: "POST" }); } catch (_) { /* best effort */ }
  state.alerts = []; state.overview = null; state.forecast = null;
  state.invoices = []; state.expenses = []; state.selected = null;
  showLogin();
}

/* ---------------- data loading ---------------- */

async function loadAlerts() {
  try {
    const payload = await api("/api/alerts?limit=100&offset=0");
    state.alerts = Array.isArray(payload.items) ? payload.items : [];
    if (state.activeTab === "alerts") render();
  } catch (error) {
    $("meta").textContent = `Refresh failed: ${error.message}`;
  }
}

async function loadOverview() {
  const payload = await api("/api/overview");
  state.overview = payload;
  if (state.activeTab === "overview") render();
}

async function loadForecast() {
  const horizon = Number($("horizon").value) || 30;
  try {
    state.forecast = await api(`/api/forecast?horizon=${horizon}`);
  } catch (error) {
    state.forecast = { status: "error", error: String(error.message) };
  }
  if (state.activeTab === "overview" || state.activeTab === "forecast") renderForecast();
}

async function loadInvoices() {
  try {
    const payload = await api("/api/invoices?limit=100");
    state.invoices = Array.isArray(payload.items) ? payload.items : [];
  } catch (error) { state.invoices = []; }
  renderInvoices();
}

async function loadExpenses() {
  try {
    const payload = await api("/api/expenses?limit=100");
    state.expenses = Array.isArray(payload.items) ? payload.items : [];
  } catch (error) { state.expenses = []; }
  renderExpenses();
}

function loadAll() {
  loadOverview().catch(() => {});
  loadAlerts();
  loadForecast();
}

async function upload() {
  const input = $("upload-file");
  const out = $("upload-result");
  if (!input.files || !input.files[0]) {
    out.hidden = false;
    out.textContent = "Choose a .csv or .xlsx file first.";
    return;
  }
  const form = new FormData();
  form.append("file", input.files[0]);
  const map = $("upload-map").value.trim();
  if (map) form.append("column_map_json", map);
  out.hidden = false;
  out.textContent = "Uploading and scoring…";
  try {
    const response = await fetch("/api/ingest", { method: "POST", headers: CSRF, body: form });
    const body = await response.json();
    if (!response.ok) {
      out.textContent = `Upload failed (${response.status}): ${body.error || "unknown"}`;
    } else {
      const lines = [`Accepted ${body.accepted_count} row(s), ${body.error_count} error(s).`];
      for (const item of body.accepted || []) {
        lines.push(`row ${item.row}: ${item.transaction_id} — ${item.flagged ? "FLAGGED" : "ok"}`);
      }
      for (const item of body.errors || []) {
        lines.push(`row ${item.row}: ${item.field}: ${item.reason}`);
      }
      out.textContent = lines.join("\n");
      loadAll();
    }
  } catch (error) {
    out.textContent = `Upload failed: ${error.message}`;
  }
}

/* ---------------- tabs ---------------- */

function activateTab(name) {
  state.activeTab = name;
  for (const button of $("tabs").querySelectorAll("button")) {
    button.classList.toggle("active", button.dataset.tab === name);
  }
  for (const section of document.querySelectorAll(".tab")) {
    section.hidden = section.id !== `tab-${name}`;
  }
  if (name === "overview") render();
  if (name === "alerts") render();
  if (name === "forecast") { renderForecast(); loadForecast(); }
  if (name === "invoices") loadInvoices();
  if (name === "expenses") loadExpenses();
}

function startPolling() {
  stopPolling();
  if ($("poll").checked) state.timer = setInterval(() => {
    loadAlerts();
    if (state.activeTab === "overview") loadOverview().catch(() => {});
  }, 10000);
}
function stopPolling() { if (state.timer) { clearInterval(state.timer); state.timer = null; } }

/* ---------------- alerts rendering ---------------- */

function row(record) {
  const tx = record.transaction || {};
  const det = record.detection || {};
  const exp = record.explanation || null;
  return {
    created_at: record.created_at || "",
    event_time: tx.event_time || "",
    amount_minor: Number(tx.amount_minor) || 0,
    anomaly_score: Number(det.anomaly_score) || 0,
    threshold: Number(det.threshold) || 0,
    baseline_source: det.baseline_source || "unknown",
    trigger: det.ml_flag && det.rule_flag ? "ML+rule" : det.rule_flag ? "rule" : "ML",
    status: record.status || "unknown",
    recommended_action: (exp && exp.assessment && exp.assessment.recommended_action) || "—",
    risk_level: (exp && exp.assessment && exp.assessment.risk_level) || null,
    source: exp ? exp.source : null,
    currency: tx.currency || "USD",
    country: tx.country || "",
    account_id: tx.account_id || "",
    device_id: tx.device_id || "",
    transaction_id: record.transaction_id || "",
    policy_action: record.policy_action || "",
    attempts: record.assessment_attempts || 0,
    error: record.explanation_error || null,
    model_version: det.model_version || "",
    feature_version: det.feature_version || "",
    evidence: Array.isArray(det.evidence) ? det.evidence : [],
    assessment: (exp && exp.assessment) || null,
    provider_model: exp ? exp.provider_model || null : null,
    request_id: exp ? exp.request_id || null : null,
  };
}

function render() {
  const rows = state.alerts.map(row);
  renderCards(rows);
  renderChart(rows);
  renderTable(rows);
  $("meta").textContent =
    `${rows.length} flagged record(s) · last refresh ${new Date().toISOString()} · tenant-scoped, pseudonymous demo data`;
  if (state.selected) {
    const current = rows.find((r) => r.transaction_id === state.selected);
    if (current) renderDrawer(current); else { state.selected = null; $("drawer").hidden = true; }
  }
}

function renderCards(rows) {
  const pack = (state.overview && state.overview.overview) || {};
  const tx = pack.transactions || {};
  const ap = pack.accounts_payable || {};
  const ex = pack.expenses || {};
  const fc = pack.forecast || {};
  const baselines = (state.overview && state.overview.baselines) || {};
  const coldStart = Object.values(baselines).filter((b) => b.baseline_source === "cold_start").length;
  const cards = [
    { label: "Transactions ingested", value: tx.count ?? rows.length, kind: "info" },
    { label: "Flagged (rate)", value: `${tx.flagged ?? 0} (${num(tx.flag_rate ?? 0, 3)})`, kind: "warn" },
    { label: "Projected net 30d", value: cents(fc.projected_net_usd_cents), kind: "ok" },
    { label: "Open invoices", value: ap.open_invoices ?? 0, kind: "info" },
    { label: "Expenses pending", value: ex.pending_approval ?? 0, kind: "warn" },
    { label: "Cold-start baselines", value: coldStart, kind: coldStart ? "warn" : "ok" },
  ];
  const host = $("cards");
  clear(host);
  for (const card of cards) {
    host.appendChild(el("div", { class: `card ${card.kind}` },
      el("div", { class: "value", text: card.value }),
      el("div", { class: "label", text: card.label })));
  }
}

function renderChart(rows) {
  const host = $("chart");
  clear(host);
  $("chart-empty").hidden = rows.length > 0;
  if (!rows.length) return;

  const width = 900, height = 260, pad = { l: 52, r: 16, t: 14, b: 34 };
  const times = rows.map((r) => Date.parse(r.event_time)).filter(Number.isFinite);
  const scores = rows.map((r) => r.anomaly_score);
  const amounts = rows.map((r) => r.amount_minor);
  const t0 = Math.min(...times), t1 = Math.max(...times, t0 + 1000);
  const s0 = Math.min(...scores, ...rows.map((r) => r.threshold));
  const s1 = Math.max(...scores, ...rows.map((r) => r.threshold));
  const aMax = Math.max(...amounts, 1);
  const x = (t) => pad.l + ((t - t0) / (t1 - t0 || 1)) * (width - pad.l - pad.r);
  const y = (s) => height - pad.b - ((s - s0) / ((s1 - s0) || 1)) * (height - pad.t - pad.b);
  const radius = (a) => 3 + 7 * Math.sqrt(a / aMax);

  const canvas = svg("svg", { width, height, viewBox: `0 0 ${width} ${height}`, role: "img",
                              "aria-label": "Scatter plot of anomaly score over event time" });
  canvas.appendChild(svg("line", { class: "axis", x1: pad.l, y1: height - pad.b, x2: width - pad.r, y2: height - pad.b }));
  canvas.appendChild(svg("line", { class: "axis", x1: pad.l, y1: pad.t, x2: pad.l, y2: height - pad.b }));

  const threshold = rows[0].threshold;
  if (Number.isFinite(threshold)) {
    canvas.appendChild(svg("line", { class: "threshold", x1: pad.l, y1: y(threshold), x2: width - pad.r, y2: y(threshold) }));
    const label = svg("text", { x: pad.l + 4, y: y(threshold) - 4 });
    label.textContent = `threshold ${num(threshold)}`;
    canvas.appendChild(label);
  }

  for (const r of rows) {
    const t = Date.parse(r.event_time);
    if (!Number.isFinite(t)) continue;
    const dot = svg("circle", {
      cx: x(t), cy: y(r.anomaly_score), r: radius(r.amount_minor),
      fill: r.anomaly_score >= r.threshold ? "#f8514966" : "#58a6ff55",
      stroke: r.anomaly_score >= r.threshold ? "#f85149" : "#58a6ff",
      "stroke-width": 1.25,
    });
    const title = svg("title");
    title.textContent =
      `${r.transaction_id}\n${r.event_time}\n${money(r.amount_minor, r.currency)} ${r.country}\n` +
      `score ${num(r.anomaly_score)} / threshold ${num(r.threshold)}\nbaseline ${r.baseline_source} · ${r.status}`;
    dot.appendChild(title);
    dot.addEventListener("click", () => { state.selected = r.transaction_id; render(); });
    canvas.appendChild(dot);
  }

  const xLabel = svg("text", { x: width - pad.r, y: height - 8, "text-anchor": "end" });
  xLabel.textContent = `${new Date(t0).toISOString().slice(5, 16)} → ${new Date(t1).toISOString().slice(5, 16)} UTC`;
  canvas.appendChild(xLabel);
  const yLabel = svg("text", { x: 6, y: pad.t + 8 });
  yLabel.textContent = `score ${num(s1, 2)}`;
  canvas.appendChild(yLabel);
  host.appendChild(canvas);
}

function sortRows(rows) {
  const key = state.sortKey, dir = state.sortDir;
  return [...rows].sort((a, b) => {
    const left = a[key], right = b[key];
    if (typeof left === "number" && typeof right === "number") return (left - right) * dir;
    return String(left).localeCompare(String(right)) * dir;
  });
}

function renderTable(rows) {
  const body = $("alerts").querySelector("tbody");
  clear(body);
  for (const r of sortRows(rows)) {
    const tr = el("tr", { class: r.transaction_id === state.selected ? "selected" : "",
                          onclick: () => { state.selected = r.transaction_id; render(); } },
      el("td", { text: r.created_at.slice(0, 19).replace("T", " ") }),
      el("td", { text: r.event_time.slice(0, 19).replace("T", " ") }),
      el("td", { class: "num", text: money(r.amount_minor, r.currency) }),
      el("td", { class: "num", text: num(r.anomaly_score) }),
      el("td", {}, badge(r.baseline_source, r.baseline_source === "account" ? "assessed" : "mock")),
      el("td", { text: r.trigger }),
      el("td", {}, badge(r.status)),
      el("td", { text: r.recommended_action }));
    body.appendChild(tr);
  }
  for (const button of document.querySelectorAll("#alerts th button")) {
    const key = button.dataset.sort;
    button.textContent = key.replace(/_/g, " ") + (state.sortKey === key ? (state.sortDir === 1 ? " ▲" : " ▼") : "");
  }
}

function evidenceTable(evidence) {
  const table = el("table", { class: "evidence" },
    el("thead", {}, el("tr", {},
      el("th", {}, el("button", { type: "button", text: "id" })),
      el("th", {}, el("button", { type: "button", text: "feature" })),
      el("th", {}, el("button", { type: "button", text: "observed" })),
      el("th", {}, el("button", { type: "button", text: "baseline" })))));
  const body = el("tbody");
  for (const item of evidence) {
    body.appendChild(el("tr", {},
      el("td", { text: item.id || "" }),
      el("td", { text: item.feature || "" }),
      el("td", { class: "num", text: typeof item.observed === "number" ? num(item.observed) : String(item.observed ?? "") }),
      el("td", { class: "num", text: typeof item.baseline === "number" ? num(item.baseline) : String(item.baseline ?? item.threshold ?? "") })));
  }
  table.appendChild(body);
  return table;
}

function renderDrawer(r) {
  $("drawer").hidden = false;
  $("drawer-title").textContent = r.transaction_id;
  const body = $("drawer-body");
  clear(body);

  body.appendChild(el("h3", { text: "Transaction (pseudonymous)" }));
  body.appendChild(el("dl", { class: "kv" },
    el("dt", { text: "event_time (UTC)" }), el("dd", { text: r.event_time }),
    el("dt", { text: "amount" }), el("dd", { text: money(r.amount_minor, r.currency) }),
    el("dt", { text: "country" }), el("dd", { text: r.country }),
    el("dt", { text: "account_id" }), el("dd", { text: r.account_id }),
    el("dt", { text: "device_id" }), el("dd", { text: r.device_id })));

  body.appendChild(el("h3", { text: "Detection" }));
  body.appendChild(el("dl", { class: "kv" },
    el("dt", { text: "anomaly_score" }), el("dd", { text: num(r.anomaly_score) }),
    el("dt", { text: "threshold" }), el("dd", { text: num(r.threshold) }),
    el("dt", { text: "baseline_source" }), el("dd", { text: r.baseline_source }),
    el("dt", { text: "trigger" }), el("dd", {}, badge(r.trigger, "pending_explanation")),
    el("dt", { text: "model_version" }), el("dd", { text: r.model_version }),
    el("dt", { text: "feature_version" }), el("dd", { text: r.feature_version })));
  body.appendChild(el("p", { class: "muted",
    text: "The score measures deviation from this account's baseline (or the synthetic reference for cold-start accounts). It is not calibrated as a probability of fraud." }));

  body.appendChild(el("h3", { text: `Measured evidence (${r.evidence.length})` }));
  body.appendChild(evidenceTable(r.evidence));

  body.appendChild(el("h3", { text: "Risk assessment" }));
  if (!r.assessment) {
    body.appendChild(el("div", { class: "notice",
      text: r.error
        ? `Explanation unavailable (${r.error}) after ${r.attempts} attempt(s). The alert is retained and still routed to human review; a missing explanation never marks a transaction safe.`
        : `No explanation yet (status: ${r.status}). The scored alert already exists and is already routed to human review.` }));
    body.appendChild(el("p", {},
      el("button", { type: "button", text: r.error ? "Retry explanation" : "Request explanation",
                     onclick: () => requestAssessment(r.transaction_id) })));
  } else {
    const a = r.assessment;
    body.appendChild(el("p", {},
      badge(r.source, r.source === "qwen" ? "qwen" : "mock"),
      " ", el("span", { class: "muted", text: r.source === "qwen" ? "generated by Qwen" : "local synthetic fixture — NOT a Qwen response" })));
    if (r.source === "qwen" && (r.provider_model || r.request_id)) {
      body.appendChild(el("p", { class: "muted", text: `provider_model: ${r.provider_model || "?"} · request_id: ${r.request_id || "?"}` }));
    }
    body.appendChild(el("dl", { class: "kv" },
      el("dt", { text: "risk_level" }), el("dd", {}, badge(a.risk_level, "pending_explanation")),
      el("dt", { text: "recommended_action" }), el("dd", { text: a.recommended_action }),
      el("dt", { text: "evidence_ids cited" }), el("dd", { text: (a.evidence_ids || []).join(", ") }),
      el("dt", { text: "policy_action" }), el("dd", { text: r.policy_action })));
    body.appendChild(el("h3", { text: "Summary (model-generated text, untrusted)" }));
    body.appendChild(el("div", { class: "prose", text: a.summary || "" }));
    body.appendChild(el("h3", { text: "Plausible benign alternatives" }));
    body.appendChild(el("ul", { class: "tight" }, (a.benign_alternatives || []).map((t) => el("li", { text: t }))));
    body.appendChild(el("h3", { text: "Missing context" }));
    body.appendChild(el("ul", { class: "tight" }, (a.missing_context || []).map((t) => el("li", { text: t }))));
    body.appendChild(el("p", { class: "muted",
      text: "Recommendations are decision support only. This prototype performs no blocking, freezing, refunds, payments, or customer contact." }));
  }
}

async function requestAssessment(transactionId) {
  $("meta").textContent = `Requesting explanation for ${transactionId}…`;
  try {
    await api(`/api/alerts/${encodeURIComponent(transactionId)}/assess`,
              { method: "POST", headers: CSRF });
  } catch (error) {
    $("meta").textContent = `Assessment request failed: ${error.message}`;
  }
  await loadAlerts();
}

/* ---------------- forecast rendering ---------------- */

function forecastChart(points, hostId, height = 260) {
  const host = $(hostId);
  clear(host);
  $("forecast-empty").hidden = true;
  if (!Array.isArray(points) || points.length < 2) {
    $("forecast-empty").hidden = false;
    return;
  }
  const width = 900, pad = { l: 70, r: 16, t: 14, b: 34 };
  const values = points.flatMap((p) => [p.net_usd_cents, p.low_usd_cents, p.high_usd_cents]);
  const v0 = Math.min(...values), v1 = Math.max(...values);
  const x = (i) => pad.l + (i / (points.length - 1)) * (width - pad.l - pad.r);
  const y = (v) => height - pad.b - ((v - v0) / ((v1 - v0) || 1)) * (height - pad.t - pad.b);

  const canvas = svg("svg", { width, height, viewBox: `0 0 ${width} ${height}`, role: "img",
                              "aria-label": "Projected net cash per day with 80 percent band" });
  canvas.appendChild(svg("line", { class: "axis", x1: pad.l, y1: height - pad.b, x2: width - pad.r, y2: height - pad.b }));
  canvas.appendChild(svg("line", { class: "axis", x1: pad.l, y1: pad.t, x2: pad.l, y2: height - pad.b }));
  if (v0 < 0 && v1 > 0) {
    canvas.appendChild(svg("line", { class: "threshold", x1: pad.l, y1: y(0), x2: width - pad.r, y2: y(0) }));
  }

  const band = points.map((p, i) => `${x(i)},${y(p.high_usd_cents)}`)
    .concat(points.map((p, i) => `${x(points.length - 1 - i)},${y(points[points.length - 1 - i].low_usd_cents)}`))
    .join(" ");
  canvas.appendChild(svg("polygon", { class: "band", points: band }));

  const line = points.map((p, i) => `${x(i)},${y(p.net_usd_cents)}`).join(" ");
  canvas.appendChild(svg("polyline", { class: "forecast-line", points: line }));

  const first = svg("text", { x: pad.l, y: height - 8 });
  first.textContent = points[0].date;
  const last = svg("text", { x: width - pad.r, y: height - 8, "text-anchor": "end" });
  last.textContent = points[points.length - 1].date;
  const top = svg("text", { x: 6, y: pad.t + 8 });
  top.textContent = cents(v1);
  const bottom = svg("text", { x: 6, y: height - pad.b - 4 });
  bottom.textContent = cents(v0);
  canvas.appendChild(first); canvas.appendChild(last);
  canvas.appendChild(top); canvas.appendChild(bottom);
  host.appendChild(canvas);
}

function renderForecast() {
  forecastChart(state.forecast && state.forecast.points, "forecast-chart-large", 300);
  const detail = $("forecast-detail");
  clear(detail);
  const fc = state.forecast;
  if (!fc) return;
  if (fc.status !== "ok") {
    detail.appendChild(el("div", { class: "notice",
      text: fc.status === "insufficient_data"
        ? `Insufficient data: ${fc.coverage_days} day(s) of history; the engine needs at least 14 and refuses to guess. Upload more history on the Overview tab.`
        : `Forecast unavailable: ${fc.error || fc.status}` }));
    return;
  }
  detail.appendChild(el("dl", { class: "kv" },
    el("dt", { text: "projected net (horizon)" }),
    el("dd", { text: `${cents(fc.projected_net_usd_cents)} over ${fc.horizon_days} days` }),
    el("dt", { text: "80% interval" }),
    el("dd", { text: `${cents(fc.projected_low_usd_cents)} … ${cents(fc.projected_high_usd_cents)}` }),
    el("dt", { text: "trend" }),
    el("dd", { text: `${cents(fc.trend_per_day_usd_cents)} per day · seasonality ${num(fc.seasonality_strength, 2)}` }),
    el("dt", { text: "historical flows" }),
    el("dd", { text: `in ${cents(fc.historical_inflow_usd_cents)} · out ${cents(fc.historical_outflow_usd_cents)}` }),
    el("dt", { text: "coverage" }),
    el("dd", { text: `${fc.coverage_days} days (${fc.history_start} → ${fc.history_end})` }),
    el("dt", { text: "method" }), el("dd", { text: fc.method })));
  detail.appendChild(el("p", { class: "muted", text: fc.disclaimer }));
}

/* ---------------- invoices / expenses ---------------- */

function renderInvoices() {
  const body = $("invoices-table").querySelector("tbody");
  clear(body);
  $("invoices-empty").hidden = state.invoices.length > 0;
  for (const inv of state.invoices) {
    const risks = el("td", {},
      ...(inv.risks || []).map((risk) => badge(risk.code, risk.severity === "high" ? "bad" : risk.severity === "medium" ? "warn" : "info")));
    body.appendChild(el("tr", {},
      el("td", { text: inv.invoice_id }),
      el("td", { text: inv.vendor_id }),
      el("td", { text: inv.due_date }),
      el("td", { class: "num", text: money(inv.amount_minor, inv.currency) }),
      el("td", {}, badge(inv.status, inv.status === "open" ? "info" : "ok")),
      risks));
  }
}

function renderExpenses() {
  const body = $("expenses-table").querySelector("tbody");
  clear(body);
  $("expenses-empty").hidden = state.expenses.length > 0;
  for (const exp of state.expenses) {
    body.appendChild(el("tr", {},
      el("td", { text: exp.expense_id }),
      el("td", { text: exp.employee_id }),
      el("td", { text: exp.category }),
      el("td", { class: "num", text: money(exp.amount_minor, exp.currency) }),
      el("td", {}, badge(exp.status,
        exp.status === "auto_approved" ? "assessed" :
        exp.status === "missing_receipt" ? "mock" : "pending_explanation")),
      el("td", { text: exp.decision_reason || "" })));
  }
}

/* ---------------- assistant ---------------- */

async function ask() {
  const question = $("question").value.trim();
  const out = $("assistant-out");
  out.hidden = false;
  clear(out);
  if (question.length < 8) {
    out.appendChild(el("p", { class: "error", text: "Ask a question of at least 8 characters." }));
    return;
  }
  out.appendChild(el("p", { class: "muted", text: "Thinking…" }));
  try {
    const response = await fetch("/api/assistant/ask", {
      method: "POST", headers: { ...CSRF, "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `http_${response.status}`);
    renderAssistant(body, out);
  } catch (error) {
    clear(out);
    out.appendChild(el("div", { class: "notice", text: `Assistant unavailable: ${error.message}` }));
  }
}

function renderAssistant(body, out) {
  clear(out);
  const answer = body.answer || {};
  out.appendChild(el("p", {},
    badge(body.source || "mock", body.source === "qwen" ? "qwen" : "mock"),
    " ", el("span", { class: "muted",
      text: body.source === "qwen" ? `generated by Qwen (${body.provider_model || "?"})`
                                   : "computed locally from stored aggregates — NOT a Qwen response" })));
  out.appendChild(el("div", { class: "prose", text: answer.answer || "" }));

  if ((answer.recommendations || []).length) {
    out.appendChild(el("h3", { text: "Recommendations (decision support only)" }));
    const list = el("ul", { class: "tight" });
    for (const rec of answer.recommendations) {
      list.appendChild(el("li", {}, badge(rec.action, "info"),
        " ", el("span", { text: rec.rationale })));
    }
    out.appendChild(list);
  }
  if ((answer.caveats || []).length) {
    out.appendChild(el("h3", { text: "Caveats" }));
    out.appendChild(el("ul", { class: "tight" },
      answer.caveats.map((caveat) => el("li", { text: caveat }))));
  }
  out.appendChild(el("h3", { text: "Context pack the model saw (aggregates only)" }));
  const pack = body.pack || {};
  const table = el("table", { class: "evidence" }, el("tbody"));
  const addRow = (section, key, value) => {
    if (value === undefined || value === null) return;
    table.querySelector("tbody").appendChild(el("tr", {},
      el("td", { text: `${section}.${key}` }),
      el("td", { class: "num", text: typeof value === "number" ? num(value, 2) : String(value) })));
  };
  for (const [section, values] of Object.entries(pack)) {
    if (section === "alerts") {
      addRow(section, "count", values.count);
      continue;
    }
    if (typeof values !== "object" || values === null) continue;
    for (const [key, value] of Object.entries(values)) addRow(section, key, value);
  }
  out.appendChild(table);
}

/* ---------------- events ---------------- */

$("signin").addEventListener("click", signIn);
$("token").addEventListener("keydown", (e) => { if (e.key === "Enter") signIn(); });
$("signout").addEventListener("click", signOut);
$("refresh").addEventListener("click", () => { loadAll(); if (state.activeTab === "invoices") loadInvoices(); if (state.activeTab === "expenses") loadExpenses(); });
$("close-drawer").addEventListener("click", () => { state.selected = null; $("drawer").hidden = true; render(); });
$("poll").addEventListener("change", startPolling);
$("upload").addEventListener("click", upload);
$("ask").addEventListener("click", ask);
$("question").addEventListener("keydown", (e) => { if (e.key === "Enter") ask(); });
$("load-forecast").addEventListener("click", loadForecast);
for (const button of $("tabs").querySelectorAll("button")) {
  button.addEventListener("click", () => activateTab(button.dataset.tab));
}
for (const button of document.querySelectorAll("#alerts th button")) {
  button.addEventListener("click", () => {
    const key = button.dataset.sort;
    if (state.sortKey === key) state.sortDir *= -1;
    else { state.sortKey = key; state.sortDir = key === "created_at" || key === "amount_minor" || key === "anomaly_score" ? -1 : 1; }
    render();
  });
}
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("drawer").hidden) { state.selected = null; $("drawer").hidden = true; render(); }
});

// On load: an existing valid cookie means we can skip the login form.
loadAlerts()
  .then(() => {
    if (!$("login").hidden) return; // 401 path already switched to login
    loadAll();
  })
  .catch(() => showLogin());
