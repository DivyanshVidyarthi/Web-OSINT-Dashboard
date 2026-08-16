const API_BASE = "/api";

// ---------------------------------------------------------------------
// View switching
// ---------------------------------------------------------------------
const navItems = document.querySelectorAll(".nav-item");
navItems.forEach((btn) => {
  btn.addEventListener("click", () => {
    navItems.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    document.getElementById(`view-${btn.dataset.view}`).classList.add("active");
    if (btn.dataset.view === "history") loadHistory();
  });
});

// ---------------------------------------------------------------------
// API health indicator
// ---------------------------------------------------------------------
async function checkHealth() {
  const statusEl = document.getElementById("apiStatus");
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error("bad status");
    const data = await res.json();
    const configuredCount = Object.values(data.configured_sources || {}).filter(Boolean).length;
    statusEl.innerHTML = `<span class="dot dot-ok"></span> API online · ${configuredCount} source(s) configured`;
  } catch (err) {
    statusEl.innerHTML = `<span class="dot dot-error"></span> API unreachable`;
  }
}
checkHealth();

// ---------------------------------------------------------------------
// Scan form
// ---------------------------------------------------------------------
const form = document.getElementById("scanForm");
const input = document.getElementById("targetInput");
const scanBtn = document.getElementById("scanBtn");
const formError = document.getElementById("formError");
const emptyState = document.getElementById("emptyState");
const loadingState = document.getElementById("loadingState");
const resultsEl = document.getElementById("results");
const loadingText = document.getElementById("loadingText");

const LOADING_MESSAGES = [
  "Querying public sources…",
  "Resolving DNS records…",
  "Checking WHOIS registry…",
  "Cross-referencing threat intelligence…",
];

let currentResult = null;

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = input.value.trim();
  formError.classList.add("hidden");
  if (!target) return;

  scanBtn.disabled = true;
  emptyState.classList.add("hidden");
  resultsEl.classList.add("hidden");
  loadingState.classList.remove("hidden");

  let msgIndex = 0;
  loadingText.textContent = LOADING_MESSAGES[0];
  const loadingInterval = setInterval(() => {
    msgIndex = (msgIndex + 1) % LOADING_MESSAGES.length;
    loadingText.textContent = LOADING_MESSAGES[msgIndex];
  }, 1400);

  try {
    const res = await fetch(`${API_BASE}/investigate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    const data = await res.json();

    if (!res.ok) {
      formError.textContent = data.detail || "Investigation failed.";
      formError.classList.remove("hidden");
      loadingState.classList.add("hidden");
      emptyState.classList.remove("hidden");
      return;
    }

    currentResult = data;
    renderResults(data);
    loadingState.classList.add("hidden");
    resultsEl.classList.remove("hidden");
  } catch (err) {
    formError.textContent = "Could not reach the API. Is the backend running?";
    formError.classList.remove("hidden");
    loadingState.classList.add("hidden");
    emptyState.classList.remove("hidden");
  } finally {
    clearInterval(loadingInterval);
    scanBtn.disabled = false;
  }
});

// ---------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------
function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  Object.entries(props).forEach(([k, v]) => {
    if (k === "className") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "html") node.innerHTML = v;
    else node.setAttribute(k, v);
  });
  children.forEach((c) => node.appendChild(c));
  return node;
}

function kv(key, value) {
  return el("div", { className: "kv-row" }, [
    el("span", { className: "kv-key", text: key }),
    el("span", { className: "kv-val", text: value === undefined || value === null || value === "" ? "—" : String(value) }),
  ]);
}

function unavailableBlock(message) {
  return el("div", { className: "unavailable", text: message || "Not available" });
}

function sourceTag(name) {
  return el("span", { className: "source-tag", text: `Source: ${name}` });
}

function sectionCard(title, bodyNode) {
  const card = el("div", { className: "card section-card" });
  card.appendChild(el("h3", { className: "card-title", text: title }));
  const body = el("div", { className: "card-body" });
  body.appendChild(bodyNode);
  card.appendChild(body);
  return card;
}

function dnsTable(records) {
  const wrapper = el("div");
  const hasAny = Object.values(records).some((v) => v && v.length);
  if (!hasAny) {
    wrapper.appendChild(unavailableBlock("No DNS records found"));
    return wrapper;
  }
  const table = el("table", { className: "dns-table" });
  const thead = el("tr", {}, [
    el("th", { text: "Type" }),
    el("th", { text: "Value" }),
  ]);
  table.appendChild(thead);
  Object.entries(records).forEach(([type, values]) => {
    (values || []).forEach((v) => {
      table.appendChild(
        el("tr", {}, [el("td", { text: type }), el("td", { text: v })])
      );
    });
  });
  wrapper.appendChild(table);
  return wrapper;
}

function renderFindings(findings) {
  const container = document.getElementById("findingsList");
  container.innerHTML = "";
  (findings || []).forEach((f) => {
    const item = el("div", { className: `finding finding-${f.level.toLowerCase()}` }, [
      el("span", { className: "finding-level", text: f.level }),
      el("div", { className: "finding-text" }, [
        document.createTextNode(f.text),
        el("span", { className: "finding-source", text: `Source: ${f.source}` }),
      ]),
    ]);
    container.appendChild(item);
  });
}

function renderResults(data) {
  document.getElementById("resultTarget").textContent = data.target;
  document.getElementById("resultType").textContent = data.type;
  document.getElementById("resultTimestamp").textContent = data.timestamp
    ? new Date(data.timestamp).toLocaleString()
    : "";

  renderFindings(data.findings);

  const grid = document.getElementById("sectionsGrid");
  grid.innerHTML = "";

  if (data.ip_resolution) grid.appendChild(buildIpResolutionCard(data.ip_resolution));
  if (data.dns) grid.appendChild(buildDnsCard(data.dns));
  if (data.whois) grid.appendChild(buildWhoisCard(data.whois));
  if (data.ip) grid.appendChild(buildIpCard(data.ip));
  if (data.geolocation) grid.appendChild(buildGeoCard(data.geolocation));
  if (data.email) grid.appendChild(buildEmailCard(data.email));
  if (data.url) grid.appendChild(buildUrlCard(data.url));
  if (data.threat_intelligence) grid.appendChild(buildThreatIntelCard(data.threat_intelligence));
}

function buildDnsCard(dns) {
  if (!dns.available) return sectionCard("DNS Records", unavailableBlock(dns.error));
  const body = el("div");
  body.appendChild(dnsTable(dns.data.records));
  body.appendChild(sourceTag("DNS"));
  return sectionCard("DNS Records", body);
}

function buildWhoisCard(whois) {
  if (!whois.available) return sectionCard("WHOIS", unavailableBlock(whois.error));
  const d = whois.data;
  const body = el("div");
  body.appendChild(kv("Domain", d.domain));
  body.appendChild(kv("Registrar", d.registrar));
  body.appendChild(kv("Created", d.creation_date));
  body.appendChild(kv("Updated", d.updated_date));
  body.appendChild(kv("Expires", d.expiration_date));
  body.appendChild(kv("Status", (d.status || []).join(", ")));
  body.appendChild(kv("Name Servers", (d.name_servers || []).join(", ")));
  body.appendChild(sourceTag("WHOIS"));
  return sectionCard("WHOIS", body);
}

function buildIpResolutionCard(res) {
  if (!res.available) return sectionCard("IP Resolution", unavailableBlock(res.error));
  const body = el("div");
  (res.data.ip_addresses || []).forEach((ip) => body.appendChild(kv("IP Address", ip)));
  body.appendChild(sourceTag("DNS"));
  return sectionCard("IP Resolution", body);
}

function buildIpCard(ipResult) {
  if (!ipResult.available) return sectionCard("IP Intelligence", unavailableBlock(ipResult.error));
  const d = ipResult.data;
  const body = el("div");
  const c = d.classification;
  body.appendChild(kv("IP", c.ip));
  body.appendChild(kv("Version", c.version));
  body.appendChild(kv("Private range", c.is_private ? "Yes" : "No"));
  if (d.reverse_dns) {
    if (d.reverse_dns.available) {
      const ptrs = d.reverse_dns.data.ptr || [];
      body.appendChild(kv("Reverse DNS", ptrs.length ? ptrs.join(", ") : "No PTR record"));
    } else {
      body.appendChild(kv("Reverse DNS", "Not available"));
    }
  }
  if (d.note) body.appendChild(el("p", { className: "card-note", text: d.note }));
  body.appendChild(sourceTag("IP Intelligence"));
  return sectionCard("IP Information", body);
}

function buildGeoCard(geo) {
  if (!geo.available) return sectionCard("Geolocation", unavailableBlock(geo.error));
  const d = geo.data;
  const body = el("div");
  body.appendChild(kv("Country", d.country));
  body.appendChild(kv("Region", d.region));
  body.appendChild(kv("City", d.city));
  body.appendChild(kv("Lat / Lon", d.latitude && d.longitude ? `${d.latitude}, ${d.longitude}` : "—"));
  body.appendChild(kv("ISP", d.isp));
  body.appendChild(kv("Organization", d.organization));
  body.appendChild(kv("ASN", d.asn));
  body.appendChild(kv("Hosting provider", d.is_hosting_provider ? "Yes" : "No"));
  body.appendChild(kv("Proxy / VPN flag", d.is_proxy_or_vpn ? "Yes" : "No"));
  body.appendChild(el("p", { className: "card-note", text: d.accuracy_notice }));
  body.appendChild(sourceTag("IP Geolocation API"));
  return sectionCard("Geolocation & ASN", body);
}

function buildEmailCard(emailResult) {
  if (!emailResult.available) return sectionCard("Email Intelligence", unavailableBlock(emailResult.error));
  const d = emailResult.data;
  const body = el("div");
  body.appendChild(kv("Email", d.email));
  body.appendChild(kv("Format valid", d.format_valid ? "Yes" : "No"));
  body.appendChild(kv("Domain", d.domain));
  body.appendChild(kv("Domain resolves", d.domain_resolves ? "Yes" : "No"));
  body.appendChild(kv("Has mail server (MX)", d.has_mail_server ? "Yes" : "No"));
  body.appendChild(kv("Disposable domain", d.is_disposable_domain ? "Yes" : "No"));
  body.appendChild(kv("Breach/reputation", d.breach_reputation?.note || "Not available"));
  body.appendChild(el("p", { className: "card-note", text: d.scope_note }));
  body.appendChild(sourceTag("Email OSINT"));
  return sectionCard("Email Intelligence", body);
}

function buildUrlCard(urlResult) {
  if (!urlResult.available) return sectionCard("URL Information", unavailableBlock(urlResult.error));
  const d = urlResult.data.parsed;
  const body = el("div");
  body.appendChild(kv("Protocol", d.protocol));
  body.appendChild(kv("Domain", d.domain));
  body.appendChild(kv("Port", d.port));
  body.appendChild(kv("Path", d.path));
  body.appendChild(kv("Query params", Object.keys(d.query_parameters || {}).length
    ? JSON.stringify(d.query_parameters) : "None"));
  body.appendChild(kv("Fragment", d.fragment || "None"));

  const http = urlResult.data.http;
  if (http) {
    if (http.available) {
      body.appendChild(kv("HTTP status", http.data.status_code));
      body.appendChild(kv("Final URL", http.data.final_url));
    } else {
      body.appendChild(kv("HTTP probe", http.error));
    }
  }
  body.appendChild(sourceTag("URL Analysis"));
  return sectionCard("URL Information", body);
}

function buildThreatIntelCard(ti) {
  const body = el("div");
  const entries = Object.entries(ti || {});
  if (!entries.length) {
    body.appendChild(unavailableBlock("No threat intelligence sources applicable"));
  } else {
    entries.forEach(([key, result]) => {
      const block = el("div", { style: "margin-bottom: 14px;" });
      block.appendChild(el("div", { className: "kv-key", text: result.source, style: "margin-bottom:4px;font-weight:600;color:var(--text-secondary);" }));
      if (!result.available) {
        block.appendChild(unavailableBlock(result.error));
      } else {
        Object.entries(result.data).forEach(([k, v]) => {
          if (Array.isArray(v)) v = v.join(", ") || "None";
          if (typeof v === "boolean") v = v ? "Yes" : "No";
          block.appendChild(kv(k.replace(/_/g, " "), v));
        });
      }
      body.appendChild(block);
    });
  }
  return sectionCard("Threat Intelligence", body);
}

// ---------------------------------------------------------------------
// Export report
// ---------------------------------------------------------------------
document.getElementById("exportBtn").addEventListener("click", () => {
  if (!currentResult) return;
  const report = buildTextReport(currentResult);
  const blob = new Blob([report], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `osint-report-${currentResult.target.replace(/[^a-z0-9.]/gi, "_")}.txt`;
  a.click();
  URL.revokeObjectURL(url);
});

function buildTextReport(data) {
  const lines = [];
  lines.push("OSINT DASHBOARD — INVESTIGATION REPORT");
  lines.push("=".repeat(50));
  lines.push(`Target: ${data.target}`);
  lines.push(`Type: ${data.type}`);
  lines.push(`Timestamp: ${data.timestamp}`);
  lines.push("");
  lines.push("This report contains information collected from publicly available sources.");
  lines.push("Results may be incomplete or inaccurate and should be independently verified.");
  lines.push("");
  lines.push("FINDINGS");
  lines.push("-".repeat(50));
  (data.findings || []).forEach((f) => {
    lines.push(`[${f.level}] ${f.text} (Source: ${f.source})`);
  });
  lines.push("");

  const sectionOrder = ["ip_resolution", "dns", "whois", "ip", "geolocation", "email", "url", "threat_intelligence"];
  sectionOrder.forEach((key) => {
    if (!data[key]) return;
    lines.push(key.toUpperCase().replace(/_/g, " "));
    lines.push("-".repeat(50));
    lines.push(JSON.stringify(data[key], null, 2));
    lines.push("");
  });

  return lines.join("\n");
}

// ---------------------------------------------------------------------
// History view
// ---------------------------------------------------------------------
async function loadHistory() {
  const listEl = document.getElementById("historyList");
  const emptyEl = document.getElementById("historyEmpty");
  listEl.innerHTML = "";
  try {
    const res = await fetch(`${API_BASE}/investigations`);
    const items = await res.json();
    if (!items.length) {
      emptyEl.classList.remove("hidden");
      return;
    }
    emptyEl.classList.add("hidden");
    items.forEach((item) => {
      const row = el("div", { className: "history-item" }, [
        el("div", { className: "history-main" }, [
          el("span", { className: "badge-type", text: item.target_type }),
          el("div", {}, [
            el("div", { className: "history-target", text: item.target }),
            el("div", { className: "history-meta", text: `${new Date(item.created_at).toLocaleString()} · ${item.status}` }),
          ]),
        ]),
        el("div", { className: "history-actions" }, [
          el("button", { text: "Open" }),
          el("button", { text: "Delete" }),
        ]),
      ]);
      const [openBtn, deleteBtn] = row.querySelectorAll("button");
      openBtn.addEventListener("click", async () => {
        const detail = await fetch(`${API_BASE}/investigations/${item.id}`).then((r) => r.json());
        currentResult = detail.result;
        renderResults(detail.result);
        document.querySelector('.nav-item[data-view="scan"]').click();
        emptyState.classList.add("hidden");
        resultsEl.classList.remove("hidden");
      });
      deleteBtn.addEventListener("click", async () => {
        await fetch(`${API_BASE}/investigations/${item.id}`, { method: "DELETE" });
        loadHistory();
      });
      listEl.appendChild(row);
    });
  } catch (err) {
    listEl.innerHTML = "";
    emptyEl.classList.remove("hidden");
  }
}

document.getElementById("clearHistoryBtn").addEventListener("click", async () => {
  await fetch(`${API_BASE}/investigations`, { method: "DELETE" });
  loadHistory();
});
