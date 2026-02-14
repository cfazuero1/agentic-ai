
from __future__ import annotations
from _keys import LOG_ANALYTICS_WORKSPACE_ID
import json
import uuid
import time
from datetime import datetime, timezone
from typing import Dict, Any, List

from flask import Flask, request, render_template_string, redirect, url_for, send_file, flash

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from openai import OpenAI

import UTILITIES
import MODEL_MANAGEMENT
import PROMPT_MANAGEMENT
import EXECUTOR
import GUARDRAILS
import PLAYBOOK
import _keys

# Build Azure + OpenAI clients
law_client = LogsQueryClient(credential=DefaultAzureCredential())
openai_client = OpenAI(api_key=_keys.OPENAI_API_KEY)
#model = MODEL_MANAGEMENT.DEFAULT_MODEL

app = Flask(__name__)
app.secret_key = "agentic-web-secret"

RUNS: Dict[str, Dict[str, Any]] = {}

def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def _parse_fields(fields_raw: str):
    if not fields_raw:
        return []

    # Replace newlines with commas
    cleaned = fields_raw.replace("\n", ",")

    # Split by comma
    parts = cleaned.split(",")

    # Trim whitespace
    fields = [p.strip() for p in parts if p.strip()]

    return fields

INDEX_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Agentic SOC Analyst</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #fafafa; }
    .container { max-width: 1100px; margin: 0 auto; }
    .sub { color: #555; margin-top: 0; }
    .card { background:#fff; border:1px solid #ddd; border-radius: 10px; padding: 16px; margin-top: 16px; }
    label { display:block; font-weight: 600; margin-top: 12px; }
    input, select, textarea { width: 100%; padding: 10px; border-radius: 8px; border:1px solid #ccc; box-sizing:border-box; }
    textarea { height: 110px; }
    .row { display:flex; gap: 16px; }
    .col { flex: 1; }
    .help { color:#666; font-size: 12px; margin-top: 4px; }
    .btn { margin-top: 16px; padding: 10px 14px; border-radius: 8px; border:0; cursor:pointer; background:#1f6feb; color:#fff; }
    .flash { background:#fff7d6; border:1px solid #ffe08a; padding:10px; border-radius:8px; margin-top:12px; }
    .multi { height: 190px; }
    code { background:#f2f2f2; padding: 2px 6px; border-radius: 6px; }

    /* ===== Loading overlay ===== */
    .overlay {
      position: fixed;
      inset: 0;
      background: rgba(250, 250, 250, 0.88);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 9999;
    }
    .overlay-card {
      background: #fff;
      border: 1px solid #e6e8f0;
      border-radius: 14px;
      padding: 18px 20px;
      box-shadow: 0 10px 28px rgba(0,0,0,0.10);
      max-width: 520px;
      width: calc(100% - 48px);
    }
    .overlay-row { display:flex; align-items:center; gap: 12px; }
    .overlay-title {
      font-weight: 800;
      margin: 0 0 4px 0;
      font-size: 16px;
      color: #111;
    }
    .overlay-sub {
      margin: 0;
      color: #555;
      font-size: 13px;
      line-height: 1.35;
    }
    .spinner {
      width: 28px;
      height: 28px;
      border-radius: 999px;
      border: 3px solid #e6e8f0;
      border-top-color: #1f6feb;
      animation: spin 1s linear infinite;
      flex: 0 0 auto;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    /* ===== end overlay ===== */
  </style>
</head>
<body>

<!-- Loading overlay -->
<div class="overlay" id="loadingOverlay" aria-hidden="true">
  <div class="overlay-card" role="status" aria-live="polite">
    <div class="overlay-row">
      <div class="spinner" aria-hidden="true"></div>
      <div>
        <p class="overlay-title">Please wait…</p>
        <p class="overlay-sub">Running the hunt and generating findings. This can take a moment.</p>
      </div>
    </div>
  </div>
</div>

<div class="container">
  <h1>Agentic SOC Analyst</h1>
  <p class="sub">Select an allowed model, table, and fields. Add/remove fields using multi-select. No free-text field names.</p>

  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="flash">
        {% for message in messages %}<div>{{ message }}</div>{% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  <div class="card">
    <form method="post" action="/hunt" id="huntForm">
      <label>Hunt Prompt</label>
      <textarea name="hunt_prompt" placeholder="Example: I'm worried windows-target-1 might have been maliciously logged into in the last few days.">{{ default.hunt_prompt }}</textarea>

      <div class="row">
        <div class="col">
          <label>Model</label>
          <select name="openai_model" id="modelSelect"></select>
          <div class="help">Only allowed models are shown.</div>
        </div>
        <div class="col">
          <label>Table</label>
          <select name="table_name" id="tableSelect"></select>
          <div class="help">Only allowed tables are shown.</div>
        </div>
      </div>

      <div class="row">
        <div class="col">
          <label>Fields (allowed)</label>
          <select class="multi" name="fields" id="fieldsSelect" multiple></select>
          <div class="help">Hold Ctrl/⌘ to select multiple. You can add/remove anytime.</div>
        </div>
      </div>

      <div class="row">
        <div class="col">
          <label>Time Range (hours)</label>
          <input name="time_range_hours" value="{{ default.time_range_hours }}"/>
        </div>
        <div class="col">
          <label>Limit</label>
          <input name="limit" value="{{ default.limit }}"/>
        </div>
      </div>

      <button class="btn" type="submit" id="runBtn">Run Hunt</button>
    </form>
  </div>
</div>

<script>
  const ALLOWED = {"DeviceProcessEvents": ["AccountName", "ActionType", "DeviceName", "InitiatingProcessCommandLine", "ProcessCommandLine", "TimeGenerated"], "DeviceNetworkEvents": ["ActionType", "DeviceName", "RemoteIP", "RemotePort", "TimeGenerated"], "DeviceLogonEvents": ["AccountName", "ActionType", "DeviceName", "RemoteDeviceName", "RemoteIP", "TimeGenerated"], "AlertInfo": [], "AlertEvidence": [], "DeviceFileEvents": ["ActionType", "DeviceName", "FileName", "FolderPath", "InitiatingProcessAccountName", "SHA256", "TimeGenerated"], "DeviceRegistryEvents": [], "AzureNetworkAnalytics_CL": ["AllowedInFlows_d", "AllowedOutFlows_d", "DeniedInFlows_d", "DeniedOutFlows_d", "DestIP_s", "DestPort_d", "FlowType_s", "SrcPublicIPs_s", "TimeGenerated", "VM_s"], "AzureActivity": ["ActivityStatusValue", "Caller", "CallerIpAddress", "Category", "OperationNameValue", "ResourceGroup", "TimeGenerated"], "SigninLogs": ["AppDisplayName", "Category", "IPAddress", "LocationDetails", "OperationName", "ResultDescription", "ResultSignature", "TimeGenerated", "UserPrincipalName"]};
  const MODELS = ["gpt-5-mini", "gpt-4.1-nano", "gpt-4.1"];

  function setOptions(selectEl, options, selectedSet) {
    selectEl.innerHTML = "";
    for (const opt of options) {
      const o = document.createElement("option");
      o.value = opt;
      o.textContent = opt;
      if (selectedSet && selectedSet.has(opt)) o.selected = true;
      selectEl.appendChild(o);
    }
  }

  function init() {
    const modelSelect = document.getElementById("modelSelect");
    const tableSelect = document.getElementById("tableSelect");
    const fieldsSelect = document.getElementById("fieldsSelect");

    // Models
    const defaultModel = "{{ default.openai_model }}" || (MODELS[0] || "");
    setOptions(modelSelect, MODELS, new Set([defaultModel]));

    // Tables
    const tables = Object.keys(ALLOWED).sort();
    const selectedTable = "DeviceProcessEvents";
    setOptions(tableSelect, tables, new Set([selectedTable]));

    // Fields
    const defaultFieldsStr = "AccountName, ActionType, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine, TimeGenerated";
    const defaultFields = new Set(defaultFieldsStr ? defaultFieldsStr.split(",").map(s => s.trim()).filter(Boolean) : []);

    function refreshFieldsForTable(t, keepSelection) {
      const fields = (ALLOWED[t] || []);
      const selected = new Set();
      if (keepSelection) {
        for (const f of defaultFields) {
          if (fields.includes(f)) selected.add(f);
        }
      }
      setOptions(fieldsSelect, fields, selected);
    }

    tableSelect.addEventListener("change", () => {
      refreshFieldsForTable(tableSelect.value, false);
    });

    refreshFieldsForTable(selectedTable, true);
  }

  init();

  // Show "Please wait..." overlay on submit
  const form = document.getElementById("huntForm");
  const overlay = document.getElementById("loadingOverlay");
  const runBtn = document.getElementById("runBtn");

  form.addEventListener("submit", () => {
    overlay.style.display = "flex";
    overlay.setAttribute("aria-hidden", "false");
    runBtn.disabled = true;
    runBtn.textContent = "Running…";
  });
</script>
</body>
</html>
"""

RESULTS_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Results</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #f6f7fb; color:#111; }
    .container { max-width: 1100px; margin: 0 auto; }
    .topbar { display:flex; align-items: baseline; justify-content: space-between; gap: 12px; }
    h1 { margin: 0 0 6px 0; }
    .meta { color:#555; font-size: 13px; }

    .grid { display:grid; grid-template-columns: 1fr; gap: 16px; margin-top: 16px; }
    @media (min-width: 960px) {
      .grid { grid-template-columns: 420px 1fr; }
    }

    .card { background:#fff; border:1px solid #e6e8f0; border-radius: 14px; padding: 16px; box-shadow: 0 1px 1px rgba(0,0,0,0.02); }
    .card h3 { margin: 0 0 10px 0; font-size: 16px; }
    .card h4 { margin: 16px 0 8px 0; font-size: 14px; color:#222; }

    .kv { display:grid; grid-template-columns: 160px 1fr; gap: 8px 12px; font-size: 13px; }
    .k { color:#666; }
    .v { color:#111; word-break: break-word; }

    .badges { display:flex; flex-wrap: wrap; gap: 8px; }
    .badge { font-size: 12px; padding: 6px 10px; border-radius: 999px; border:1px solid #e6e8f0; background:#f8f9ff; }

    .divider { height:1px; background:#eef0f6; margin: 14px 0; }

    .btnrow { display:flex; gap: 10px; flex-wrap: wrap; margin-top: 10px; }
    a.btn { display:inline-block; padding: 10px 14px; border-radius: 10px; background:#1f6feb; color:#fff; text-decoration:none; font-weight: 600; font-size: 13px; }
    a.btn.secondary { background:#555; }

    .finding { border:1px solid #e6e8f0; border-radius: 14px; padding: 14px; margin-top: 12px; }
    .finding-header { display:flex; justify-content: space-between; gap: 12px; align-items: flex-start; }
    .finding-title { font-weight: 700; font-size: 14px; margin:0; }
    .pill { font-size: 12px; padding: 5px 10px; border-radius: 999px; border:1px solid #e6e8f0; background:#f7f8ff; white-space: nowrap; }

    .finding-body { margin-top: 10px; display:grid; gap: 10px; }
    .section { background:#fafbff; border:1px solid #eef0f6; border-radius: 12px; padding: 10px 12px; }
    .section-title { font-size: 12px; font-weight: 700; color:#333; margin-bottom: 6px; text-transform: uppercase; letter-spacing: .02em; }
    .section p { margin: 0; font-size: 13px; color:#111; white-space: pre-wrap; }

    .list { margin:0; padding-left: 18px; font-size: 13px; }
    .muted { color:#666; font-size: 12px; }
    .error { color:#b42318; background:#fff1f0; border:1px solid #ffd5d5; padding:10px; border-radius: 12px; }

    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; white-space: pre-wrap; }
  </style>
</head>
<body>
<div class="container">

  <div class="topbar">
    <div>
      <h1>Results</h1>
      <div class="meta">Run: <b>{{ run_id }}</b> • Generated: {{ generated }}</div>
    </div>
    <div class="btnrow">
      <a class="btn" href="{{ url_for('download_playbook', run_id=run_id) }}">Download Playbook (PDF)</a>
      <a class="btn secondary" href="{{ url_for('index') }}">Back</a>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Search Summary</h3>
      <div id="summary" class="kv"></div>

      <div class="divider"></div>

      <h4>Selected Fields</h4>
      <div id="fieldsBadges" class="badges"></div>

      <div class="divider"></div>

      <h4>Rationale</h4>
      <div id="rationale" class="muted">—</div>
    </div>

    <div class="card">
      <h3>Findings</h3>
      <div class="muted">Readable investigation summary.</div>
      <div id="findingsRoot"></div>
    </div>
  </div>

  <div class="divider"></div>

  <h3>Executed Search Query</h3>
  <div class="muted">This is the exact KQL sent to Microsoft Sentinel.</div>

  <div class="section" style="margin-top:10px;">
    <div class="section-title">KQL Query</div>
    <pre class="mono">{{ executed_kql }}</pre>
  </div>

</div>

<script>
  const queryContextJson = {{ context | tojson }};
  const findingsJson = {{ findings | tojson }};

  function safeParse(label, value) {
    try { return JSON.parse(value); }
    catch (e) { return { __parse_error: true }; }
  }

  const ctx = safeParse("query context", queryContextJson);
  const findings = safeParse("findings", findingsJson);

  function pick(obj, keys) {
    for (const k of keys) {
      if (obj && obj[k] !== undefined && obj[k] !== null && obj[k] !== "") return obj[k];
    }
    return null;
  }

  function addKV(root, k, v) {
    const kEl = document.createElement("div");
    kEl.className = "k";
    kEl.textContent = k;

    const vEl = document.createElement("div");
    vEl.className = "v";
    vEl.textContent = (v === null || v === undefined || v === "") ? "—" : String(v);

    root.appendChild(kEl);
    root.appendChild(vEl);
  }

  // Render Search Summary (left card)
  const summary = document.getElementById("summary");
  const fieldsBadges = document.getElementById("fieldsBadges");
  const rationaleEl = document.getElementById("rationale");

  if (!ctx.__parse_error) {
    addKV(summary, "Table", ctx.table_name || "—");
    addKV(summary, "Time range", ctx.time_range_hours ? `${ctx.time_range_hours} hours` : "—");
    addKV(summary, "Device", ctx.device_name || "—");
    addKV(summary, "Caller", ctx.caller || "—");
    addKV(summary, "UPN", ctx.user_principal_name || "—");

    // Normalize fields
    let fieldsArr = [];
    if (Array.isArray(ctx.fields)) fieldsArr = ctx.fields;
    else if (typeof ctx.fields === "string") {
      fieldsArr = ctx.fields.split(",").map(s => s.trim()).filter(Boolean);
    }

    // Render field badges
    fieldsBadges.innerHTML = "";
    if (fieldsArr.length === 0) {
      const b = document.createElement("span");
      b.className = "badge";
      b.textContent = "No fields selected";
      fieldsBadges.appendChild(b);
    } else {
      fieldsArr.forEach(f => {
        const b = document.createElement("span");
        b.className = "badge";
        b.textContent = f;
        fieldsBadges.appendChild(b);
      });
    }

    // Rationale
    rationaleEl.textContent = ctx.rationale || "—";
  } else {
    summary.innerHTML = "<div class='error'>Query context could not be parsed.</div>";
    fieldsBadges.innerHTML = "";
    rationaleEl.textContent = "—";
  }

  function renderMitre(mitre) {
    if (!mitre) return null;

    const section = document.createElement("div");
    section.className = "section";
    section.innerHTML = `<div class="section-title">MITRE Mapping</div>`;

    // Pretty render by common keys if present, else generic
    const p = document.createElement("p");
    p.className = "mono";

    if (Array.isArray(mitre)) {
      p.textContent = mitre.map(x => (typeof x === "object" ? JSON.stringify(x, null, 2) : String(x))).join("\\n");
    } else if (typeof mitre === "object") {
      // try friendly ordering
      const lines = [];
      const order = ["tactic", "technique", "sub_technique", "id", "name", "description"];
      order.forEach(k => {
        if (mitre[k] !== undefined && mitre[k] !== null && mitre[k] !== "") {
          const v = mitre[k];
          lines.push(`${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`);
        }
      });
      // add any remaining keys
      Object.keys(mitre).forEach(k => {
        if (order.includes(k)) return;
        const v = mitre[k];
        lines.push(`${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`);
      });
      p.textContent = lines.join("\\n");
    } else {
      p.textContent = String(mitre);
    }

    section.appendChild(p);
    return section;
  }

  function renderFinding(f, idx) {
    const wrap = document.createElement("div");
    wrap.className = "finding";

    const header = document.createElement("div");
    header.className = "finding-header";

    const title = document.createElement("p");
    title.className = "finding-title";
    title.textContent = pick(f, ["title", "finding", "summary", "name"]) || `Finding #${idx+1}`;

    const right = document.createElement("div");
    const sev = pick(f, ["severity", "risk", "level"]) || "";
    const conf = pick(f, ["confidence"]) || "";

    if (sev) {
      const pill = document.createElement("span");
      pill.className = "pill";
      pill.textContent = `Severity: ${sev}`;
      right.appendChild(pill);
    }
    if (conf) {
      const pill = document.createElement("span");
      pill.className = "pill";
      pill.style.marginLeft = "8px";
      pill.textContent = `Confidence: ${conf}`;
      right.appendChild(pill);
    }

    header.appendChild(title);
    header.appendChild(right);
    wrap.appendChild(header);

    const body = document.createElement("div");
    body.className = "finding-body";

    const evidence = pick(f, ["evidence", "supporting_evidence", "observations", "details"]);
    if (evidence) {
      const s = document.createElement("div");
      s.className = "section";
      s.innerHTML = `<div class="section-title">What we observed</div><p></p>`;
      s.querySelector("p").textContent = String(evidence);
      body.appendChild(s);
    }

    const impact = pick(f, ["impact", "business_impact"]);
    if (impact) {
      const s = document.createElement("div");
      s.className = "section";
      s.innerHTML = `<div class="section-title">Impact</div><p></p>`;
      s.querySelector("p").textContent = String(impact);
      body.appendChild(s);
    }

    const reco = pick(f, ["recommendation", "recommendations", "next_steps", "mitigation"]);
    if (reco) {
      const s = document.createElement("div");
      s.className = "section";
      s.innerHTML = `<div class="section-title">Recommended actions</div><p></p>`;
      s.querySelector("p").textContent = String(reco);
      body.appendChild(s);
    }

    const kql = pick(f, ["kql", "query", "kusto"]);
    if (kql) {
      const s = document.createElement("div");
      s.className = "section";
      s.innerHTML = `<div class="section-title">Suggested query</div><p class="mono"></p>`;
      s.querySelector("p").textContent = String(kql);
      body.appendChild(s);
    }

    const mitreSection = renderMitre(pick(f, ["mitre", "mitre_attack", "techniques", "tactics"]));
    if (mitreSection) body.appendChild(mitreSection);

    // Fallback if model returns an object but no known keys matched
    if (body.children.length === 0 && f && typeof f === "object") {
      const s = document.createElement("div");
      s.className = "section";
      s.innerHTML = `<div class="section-title">Details</div>`;
      const ul = document.createElement("ul");
      ul.className = "list";
      Object.keys(f).forEach(k => {
        const li = document.createElement("li");
        const val = f[k];
        li.textContent = `${k}: ${Array.isArray(val) ? val.join(", ") : String(val)}`;
        ul.appendChild(li);
      });
      s.appendChild(ul);
      body.appendChild(s);
    }

    wrap.appendChild(body);
    return wrap;
  }

  const root = document.getElementById("findingsRoot");

  if (findings.__parse_error) {
    root.innerHTML = `<div class="error">Findings could not be parsed.</div>`;
  } else if (!Array.isArray(findings) || findings.length === 0) {
    root.innerHTML = `<div class="muted">No findings were returned.</div>`;
  } else {
    findings.forEach((f, idx) => root.appendChild(renderFinding(f, idx)));
  }
</script>
</body>
</html>
"""

@app.get("/")
def index():
    default = {
        "hunt_prompt": "",
        "table_name": "DeviceProcessEvents",
        "fields": "TimeGenerated, DeviceName, AccountName, ActionType, ProcessCommandLine",
        "time_range_hours": "96",
        "limit": "200",
        "device_name": "",
        "caller": "",
        "user_principal_name": "",
    }
    return render_template_string(INDEX_HTML, default=default)

@app.post("/hunt")
def hunt():
    try:
        hunt_prompt = (request.form.get("hunt_prompt", "") or "").strip()
        openai_model = (request.form.get("openai_model") or "gpt-5-mini").strip()
        table_name = (request.form.get("table_name", "") or "").strip()
        fields_raw = (request.form.get("fields", "") or "").strip()

        # Defaults if user leaves blank
        time_range_hours_raw = (request.form.get("time_range_hours", "") or "").strip()
        limit_raw = (request.form.get("limit", "") or "").strip()
        time_range_hours = int(time_range_hours_raw) if time_range_hours_raw else 72
        limit = int(limit_raw) if limit_raw else 200
        #openai_model = MODEL_MANAGEMENT.DEFAULT_MODEL
        device_name = (request.form.get("device_name", "") or "").strip()
        caller = (request.form.get("caller", "") or "").strip()
        user_principal_name = (request.form.get("user_principal_name", "") or "").strip()

        if not hunt_prompt:
            flash("Hunt prompt is required.")
            return redirect(url_for("index"))
        if not table_name:
            flash("Table name is required.")
            return redirect(url_for("index"))

        fields = _parse_fields(fields_raw)
        if not fields:
            flash("At least one field is required.")
            return redirect(url_for("index"))

        # Build query context from USER input (full user control)
        unformatted_query_context = {
            "table_name": table_name,
            "fields": fields,
            "time_range_hours": time_range_hours,
            "device_name": device_name,
            "caller": caller,
            "user_principal_name": user_principal_name
        }
        
        user_message = {
        "role": "user",
        "content": hunt_prompt
        }
        # return an object that describes the user's request as well as where and how the agent has decided to search
        unformatted_query_context = EXECUTOR.get_query_context(openai_client, user_message, model=openai_model)
        # sanitize values & normalize field formats (same step as _main.py)
        query_context = UTILITIES.sanitize_query_context(unformatted_query_context)
        print(type(unformatted_query_context))
        # Validate allowed tables/fields (same as _main.py)
        GUARDRAILS.validate_tables_and_fields(query_context["table_name"], query_context["fields"])

        # Query Log Analytics (same function as _main.py)
        law_query_results = EXECUTOR.query_log_analytics(
            log_analytics_client=law_client,
            workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
            timerange_hours=query_context["time_range_hours"],
            table_name=query_context["table_name"],
            device_name=query_context["device_name"],
            fields=query_context["fields"],
            caller=query_context["caller"],
            user_principal_name=query_context["user_principal_name"],
            limit=limit
        )

        if law_query_results["count"] == 0:
            flash("No records returned from Log Analytics for that query.")
            return redirect(url_for("index"))

        # Build the hunt prompt for the LLM (same as _main.py)
        threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
            user_prompt=hunt_prompt,
            table_name=query_context["table_name"],
            log_data=law_query_results["records"]
        )

        messages = [PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT, threat_hunt_user_message]

        executed_kql = law_query_results.get("user_query", "")
        token_count = MODEL_MANAGEMENT.count_tokens(messages, openai_model)
        model = MODEL_MANAGEMENT.choose_model(openai_model, token_count)
        GUARDRAILS.validate_model(model)

        start = time.time()
        hunt_results = EXECUTOR.hunt(
            openai_client=openai_client,
            threat_hunt_system_message=PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT,
            threat_hunt_user_message=threat_hunt_user_message,
            openai_model=openai_model
        )
        _ = time.time() - start

        run_id = uuid.uuid4().hex[:8]
        RUNS[run_id] = {
            "query_context": query_context,
            "findings": (hunt_results or {}).get("findings", []),
            "generated": now_utc(),
            "executed_kql": executed_kql
        }

        return render_template_string(
            RESULTS_HTML,
            context=json.dumps(query_context, indent=2),
            findings=json.dumps((hunt_results or {}).get("findings", []), indent=2),
            run_id=run_id,
            generated=RUNS[run_id]["generated"],
            executed_kql=RUNS[run_id]["executed_kql"]  
        )

    except Exception as e:
        flash(f"Guardrails blocked the request: {str(e)}")
        return redirect(url_for("index"))

@app.get("/download/playbook/<run_id>")
def download_playbook(run_id):
    run = RUNS.get(run_id)
    if not run:
        flash("Run not found (server restarted).")
        return redirect(url_for("index"))

    pdf_bytes = PLAYBOOK.build_playbook_pdf(
        query_context=run["query_context"],
        findings=run["findings"],
        generated_by="Agentic Web SOC"
    )

    from io import BytesIO
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"mitigation_playbook_{run_id}.pdf"
    )

if __name__ == "__main__":
    app.run(debug=True)
