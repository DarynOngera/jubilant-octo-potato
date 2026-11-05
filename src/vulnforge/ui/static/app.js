/* Vanilla JS dashboard for the local VulnForge UI. */
(() => {
  "use strict";

  const state = {
    session: null,
    actions: [],
    portfolio: null,
    matrix: null,
    detail: null,
    jobs: [],
    poll: null,
    modalOpen: false,
    modalJobId: null,
    matrixSort: { key: "priority_P", dir: -1 },
  };

  const main = document.getElementById("main");
  const modal = document.getElementById("modal");
  const modalBody = document.getElementById("modal-body");
  const modalTitle = document.getElementById("modal-title");
  const toastEl = document.getElementById("toast");

  // -- utilities --------------------------------------------------------

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[ch]));
  }

  function dash(value) {
    return value === null || value === undefined || value === "" ? "—" : esc(value);
  }

  function fmtMiB(value) {
    if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
    return `${(Number(value) / 1048576).toFixed(2)} MiB`;
  }

  function fmtNumber(value, digits = 2) {
    if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
    return Number(value).toFixed(digits);
  }

  function fmtDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return esc(value);
    return esc(date.toISOString().replace("T", " ").replace(".000Z", "Z"));
  }

  function badge(text, kind = "neutral") {
    return `<span class="badge ${kind}">${esc(text)}</span>`;
  }

  function verdictBadge(verdict) {
    const kind = { CONFIRMED: "ok", INCONCLUSIVE: "warn", FAIL: "bad", NOT_RUN: "neutral" }[verdict] || "neutral";
    return badge(verdict || "NOT_RUN", kind);
  }

  function detectionBadge(result) {
    const kind = { TRIGGERED: "bad", INCONCLUSIVE: "warn", NOT_TRIGGERED: "ok", NOT_RUN: "neutral" }[result] || "neutral";
    return badge(result || "NOT_RUN", kind);
  }

  function yesNo(ok, yes = "yes", no = "no") {
    return badge(ok ? yes : no, ok ? "ok" : "warn");
  }

  function activePage() {
    const hash = location.hash.replace(/^#\/?/, "");
    return (hash.split("/").filter(Boolean)[0]) || "overview";
  }

  function cveHref(cve, tab = "overview") {
    return `#/cve/${encodeURIComponent(cve)}/${tab}`;
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      credentials: "same-origin",
      ...options,
      headers: { Accept: "application/json", ...(options.headers || {}) },
    });
    if (!response.ok) {
      let message = `${response.status} ${response.statusText}`;
      try {
        const payload = await response.json();
        if (payload && payload.error) message = payload.error;
      } catch (_) { /* keep status text */ }
      throw new Error(message);
    }
    return response.json();
  }

  async function apiText(path) {
    const response = await fetch(path, { credentials: "same-origin" });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return response.text();
  }

  function toast(message, isError = false) {
    toastEl.textContent = message;
    toastEl.className = `toast${isError ? " error" : ""}`;
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => { toastEl.className = "toast hidden"; }, 5200);
  }

  function md(text) {
    if (!text) return '<div class="empty">Not available.</div>';
    if (window.marked && window.DOMPurify) {
      const html = window.marked.parse(text);
      return `<div class="markdown">${window.DOMPurify.sanitize(html)}</div>`;
    }
    return `<pre class="log">${esc(text)}</pre>`;
  }

  function empty(message) {
    return `<div class="empty">${esc(message)}</div>`;
  }

  function healthList(issues) {
    if (!issues || !issues.length) return '<div class="empty">No integrity issues found.</div>';
    return `<div class="health-list">${issues.map((issue) => `
      <div class="health-item">
        <span class="dot ${esc(issue.level)}"></span>
        <span>${esc(issue.message)}</span>
      </div>`).join("")}</div>`;
  }

  function packageState(cve) {
    if (!cve) return null;
    if (state.detail?.summary?.cve === cve) return state.detail.summary;
    return (state.portfolio?.packages || []).find((pkg) => pkg.cve === cve) || null;
  }

  function actionReadiness(id, cve) {
    const pkg = packageState(cve);
    return pkg?.lifecycle?.actions?.[id] || null;
  }

  function actionButton(id, cve, label) {
    const action = state.actions.find((item) => item.id === id);
    if (!action) return "";
    const readiness = actionReadiness(id, cve);
    const enabled = action.enabled && (!readiness || readiness.enabled);
    const title = !action.enabled
      ? action.disabled_reason
      : readiness && !readiness.enabled
        ? readiness.reason
        : action.description;
    const disabled = enabled ? "" : "disabled";
    return `<button class="btn small ${action.destructive ? "danger" : ""}" data-action="open-action" data-id="${esc(id)}" data-cve="${esc(cve || "")}" ${disabled} title="${esc(title)}">${esc(label || action.label)}</button>`;
  }

  function lifecycleRail(lifecycle) {
    if (!lifecycle) return "";
    const stages = ["package", "lab", "probe", "validation", "detection", "report"];
    return `<div class="lifecycle-rail">${stages.map((name) => {
      const stage = lifecycle.stages?.[name] || { ok: false, label: name };
      return `<span class="lifecycle-step ${stage.ok ? "done" : "pending"}" title="${esc(stage.label)}">
        <span class="lifecycle-dot"></span>${esc(name)}
      </span>`;
    }).join("")}</div>`;
  }

  function nextAction(summary) {
    const lifecycle = summary?.lifecycle;
    if (!lifecycle) return "";
    if (!lifecycle.next_action) {
      return `<span class="next-step complete">${esc(lifecycle.next_label)}</span>`;
    }
    const action = state.actions.find((item) => item.id === lifecycle.next_action);
    return `<span class="next-step"><span class="eyebrow">Next step</span>
      ${actionButton(lifecycle.next_action, summary.cve, lifecycle.next_label || action?.label || lifecycle.next_action)}
    </span>`;
  }

  function actionsRow(summary) {
    const cve = summary.cve;
    return `<div class="next-action-row">${nextAction(summary)}</div>
      <div class="action-groups">
        <span class="action-group"><span>Lab</span>
          ${actionButton("lab_build", cve, "Build")}
          ${actionButton("lab_start", cve, "Start")}
          ${actionButton("lab_stop", cve, "Stop")}
        </span>
        <span class="action-group"><span>Evidence</span>
          ${actionButton("poc_run", cve, "Run PoC")}
          ${actionButton("validate", cve, "Run validation")}
          ${actionButton("detect", cve, "Run detection")}
        </span>
        <span class="action-group"><span>Report</span>
          ${actionButton("report", cve, "Generate report")}
          ${actionButton("package_validate", cve, "Check package")}
        </span>
      </div>`;
  }

  function workflowStrip() {
    return `<div class="workflow-strip">
      <span><b>1</b> Pick a CVE</span><span class="workflow-arrow">→</span>
      <span><b>2</b> Scaffold package</span><span class="workflow-arrow">→</span>
      <span><b>3</b> Build / start lab</span><span class="workflow-arrow">→</span>
      <span><b>4</b> Run PoC</span><span class="workflow-arrow">→</span>
      <span><b>5</b> Validate</span><span class="workflow-arrow">→</span>
      <span><b>6</b> Detect</span><span class="workflow-arrow">→</span>
      <span><b>7</b> Report</span>
    </div>`;
  }

  // -- routing ----------------------------------------------------------

  function setNav(page) {
    document.querySelectorAll("[data-nav]").forEach((link) => {
      link.classList.toggle("active", link.dataset.nav === page);
    });
  }

  async function route() {
    if (state.poll) { clearInterval(state.poll); state.poll = null; }
    const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
    const page = parts[0] || "overview";
    setNav(page);
    main.innerHTML = '<div class="loading">Loading…</div>';
    try {
      if (page === "overview") await renderOverview();
      else if (page === "packages") await renderPackages();
      else if (page === "cve") await renderCve(parts[1], parts[2] || "overview");
      else if (page === "labs") await renderLabs();
      else if (page === "matrix") await renderMatrix();
      else if (page === "activity") await renderActivity();
      else if (page === "doctor") await renderDoctor();
      else { location.hash = "#/overview"; }
    } catch (error) {
      main.innerHTML = `<div class="card"><h1>Could not load view</h1><p class="muted">${esc(error.message)}</p></div>`;
    }
  }

  // -- overview ---------------------------------------------------------

  async function ensurePortfolio() {
    if (!state.portfolio) state.portfolio = await api("/api/status");
    return state.portfolio;
  }

  async function ensureMatrix() {
    if (!state.matrix) state.matrix = await api("/api/matrix");
    return state.matrix;
  }

  async function renderOverview() {
    const [status, matrix] = await Promise.all([ensurePortfolio(), ensureMatrix()]);
    const counts = status.counts;
    const top = [...matrix].sort((a, b) => Number(b.priority_P) - Number(a.priority_P)).slice(0, 5);
    const rows = status.packages.map((pkg) => `
      <tr>
        <td><a href="${cveHref(pkg.cve)}" class="mono">${esc(pkg.cve)}</a></td>
        <td>${esc(pkg.title)}</td>
        <td class="nowrap">${esc(pkg.vulnerable_version)} → ${esc(pkg.patched_version)}</td>
        <td class="num">${fmtMiB(pkg.validation.vulnerable_median)}</td>
        <td class="num">${fmtMiB(pkg.validation.patched_median)}</td>
        <td>${verdictBadge(pkg.verdict)}</td>
        <td>${detectionBadge(pkg.detection)}</td>
        <td>${pkg.valid ? badge("valid", "ok") : badge("invalid", "bad")}</td>
        <td>${pkg.lifecycle?.next_action
          ? actionButton(pkg.lifecycle.next_action, pkg.cve, pkg.lifecycle.next_label)
          : badge(pkg.lifecycle?.next_label || "complete", "ok")}</td>
      </tr>`).join("");

    main.innerHTML = `
      <div class="page-head">
        <div>
          <div class="eyebrow">Portfolio</div>
          <h1>Vulnerability research factory</h1>
          <p>Packages, evidence, detection, and lab state in one place. ${state.session.read_only ? "Read-only mode." : "Actions are available on loopback."}</p>
        </div>
        <div class="actions">
          ${actionButton("package_validate", "", "Check all packages")}
          ${actionButton("triage_check", "", "Check triage drift")}
          <button class="btn small" data-action="refresh-overview">Refresh</button>
        </div>
      </div>

      ${workflowStrip()}

      <section class="kpis">
        <div class="kpi accent"><div class="value">${counts.packages}</div><div class="label">packaged CVEs</div></div>
        <div class="kpi warn"><div class="value">${counts.needs_action || 0}</div><div class="label">need action</div></div>
        <div class="kpi good"><div class="value">${counts.confirmed}</div><div class="label">CONFIRMED</div></div>
        <div class="kpi warn"><div class="value">${counts.inconclusive}</div><div class="label">INCONCLUSIVE</div></div>
        <div class="kpi bad"><div class="value">${counts.triggered}</div><div class="label">detection TRIGGERED</div></div>
        <div class="kpi"><div class="value">${counts.advisories}</div><div class="label">advisories tracked</div></div>
      </section>

      <div class="grid two">
        <section class="card">
          <div class="card-head"><h2>Packages</h2><span class="muted">${status.packages.length} total</span></div>
          ${status.packages.length ? `<div class="table-wrap"><table>
            <thead><tr><th>CVE</th><th>Title</th><th>Pair</th><th class="num">Vuln median</th><th class="num">Patched median</th><th>Verdict</th><th>Detection</th><th>State</th><th>Next step</th></tr></thead>
            <tbody>${rows}</tbody>
          </table></div>` : empty("No packages yet.")}
        </section>

        <section class="card">
          <div class="card-head"><h2>Top research priority</h2><a href="#/matrix" class="muted">full matrix →</a></div>
          <div class="table-wrap"><table>
            <thead><tr><th>CVE</th><th>Track</th><th class="num">P</th><th>Tier</th></tr></thead>
            <tbody>${top.map((row) => `<tr>
              <td class="mono">${esc(row.cve)}</td>
              <td>${esc(row.track)}</td>
              <td class="num">${fmtNumber(row.priority_P)}</td>
              <td>${esc(row.exploit_tier)}</td>
            </tr>`).join("")}</tbody>
          </table></div>
        </section>
      </div>

      <section class="card" style="margin-top:16px">
        <div class="card-head"><h2>Recent package activity</h2></div>
        <div class="table-wrap"><table>
          <thead><tr><th>CVE</th><th>Last verdict run</th><th>Runs</th><th>Evidence files</th><th>Provenance</th></tr></thead>
          <tbody>${status.packages.map((pkg) => `<tr>
            <td class="mono"><a href="${cveHref(pkg.cve)}">${esc(pkg.cve)}</a></td>
            <td>${fmtDate(pkg.last_run_at)}</td>
            <td class="num">${dash(pkg.validation.runs)}</td>
            <td class="num">${dash(pkg.run_count)}</td>
            <td>${pkg.git_dirty === true ? badge("dirty", "warn") : pkg.git_dirty === false ? badge("clean", "ok") : badge("unknown", "neutral")}</td>
          </tr>`).join("")}</tbody>
        </table></div>
      </section>`;
  }

  // -- packages ---------------------------------------------------------

  async function renderPackages() {
    const status = await ensurePortfolio();
    const rows = status.packages.map((pkg) => `<tr>
      <td class="mono"><a href="${cveHref(pkg.cve)}">${esc(pkg.cve)}</a></td>
      <td>${esc(pkg.title)}</td>
      <td>${esc(pkg.target)}</td>
      <td class="nowrap">${esc(pkg.vulnerable_version)} → ${esc(pkg.patched_version)}</td>
      <td>${lifecycleRail(pkg.lifecycle)}</td>
      <td>${verdictBadge(pkg.verdict)}</td>
      <td>${detectionBadge(pkg.detection)}</td>
      <td>${pkg.lifecycle?.next_action
        ? actionButton(pkg.lifecycle.next_action, pkg.cve, pkg.lifecycle.next_label)
        : badge(pkg.lifecycle?.next_label || "complete", "ok")}</td>
    </tr>`).join("");
    main.innerHTML = `
      <div class="page-head">
        <div>
          <div class="eyebrow">Packages</div>
          <h1>Package lifecycle</h1>
          <p>Each package moves through lab → probe → validation → detection → report. The next action is the only step that is ready.</p>
        </div>
        <div class="actions">
          ${actionButton("package_scaffold", "", "New package")}
          ${actionButton("package_validate", "", "Check all packages")}
          <button class="btn small" data-action="refresh-packages">Refresh</button>
        </div>
      </div>
      ${workflowStrip()}
      <section class="card">
        ${status.packages.length ? `<div class="table-wrap"><table>
          <thead><tr><th>CVE</th><th>Title</th><th>Adapter</th><th>Pair</th><th>Lifecycle</th><th>Verdict</th><th>Detection</th><th>Next step</th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>` : empty("No packages yet. Create one with vulnforge package scaffold <CVE>.")}
      </section>`;
  }

  // -- CVE detail -------------------------------------------------------

  async function renderCve(cve, tab) {
    if (!cve) { location.hash = "#/overview"; return; }
    const detail = await api(`/api/packages/${encodeURIComponent(cve)}`);
    state.detail = detail;
    const summary = detail.summary;
    const tabs = ["overview", "validation", "detection", "evidence", "report"];
    const active = tabs.includes(tab) ? tab : "overview";
    let body = "";
    if (active === "overview") body = cveOverview(detail);
    else if (active === "validation") body = cveValidation(detail);
    else if (active === "detection") body = cveDetection(detail);
    else if (active === "evidence") body = cveEvidence(detail);
    else body = '<div id="report-body" class="muted">Loading report…</div>';

    main.innerHTML = `
      <div class="page-head">
        <div>
          <div class="eyebrow">CVE package</div>
          <h1>${esc(summary.cve)}</h1>
          <p>${esc(summary.title)}</p>
          <div class="chip-row" style="margin-top:10px">
            ${verdictBadge(summary.verdict)}
            ${detectionBadge(summary.detection)}
            ${summary.valid ? badge("package valid", "ok") : badge("package invalid", "bad")}
            ${summary.git_dirty === true ? badge("provenance dirty", "warn") : ""}
            <span class="badge neutral">${esc(summary.vulnerable_version)} → ${esc(summary.patched_version)}</span>
          </div>
          ${lifecycleRail(summary.lifecycle)}
        </div>
        <div class="actions">${actionsRow(summary)}<button class="btn small" data-action="refresh-detail" data-cve="${esc(summary.cve)}" data-tab="${esc(active)}">Refresh</button></div>
      </div>

      <div class="tabs">
        ${tabs.map((name) => `<a href="${cveHref(summary.cve, name)}" class="${name === active ? "active" : ""}">${name[0].toUpperCase()}${name.slice(1)}</a>`).join("")}
      </div>
      <div id="tab-body">${body}</div>`;

    if (active === "report") await loadReport(summary.cve);
  }

  function cveOverview(detail) {
    const summary = detail.summary;
    const advisory = detail.advisory || {};
    const exploit = detail.exploitability || {};
    const catalog = detail.catalog || {};
    const rootCause = detail.root_cause;
    const attackSurface = detail.attack_surface;
    return `
      <div class="grid two">
        <section class="card">
          <div class="card-head"><h2>Advisory</h2><span class="muted">${esc(advisory.track || "")}</span></div>
          <dl class="kv">
            <dt>Title</dt><dd>${dash(advisory.title)}</dd>
            <dt>Affected</dt><dd><code>${dash(advisory.affected)}</code></dd>
            <dt>Fixed in</dt><dd><code>${dash(advisory.fixed_in)}</code></dd>
            <dt>CVSS 4.0</dt><dd>${dash(advisory.cvss_score)} <span class="muted mono">${esc(advisory.cvss_vector || "")}</span></dd>
            <dt>Published</dt><dd>${dash(advisory.published)}</dd>
            <dt>Aliases</dt><dd>${esc([advisory.ghsa, advisory.osv].filter(Boolean).join(", ")) || "—"}</dd>
            <dt>Priority</dt><dd>${summary.priority == null ? "—" : esc(summary.priority)} <span class="muted">${esc(summary.exploit_tier || "")}</span></dd>
          </dl>
          <div class="stack" style="margin-top:14px">
            ${(advisory.references || []).map((url) => `<a class="mono" href="${esc(url)}" target="_blank" rel="noreferrer">${esc(url)}</a>`).join("")}
          </div>
        </section>

        <section class="card">
          <div class="card-head"><h2>Measured result</h2></div>
          <div class="kpis" style="margin:0 0 12px">
            <div class="kpi"><div class="value">${fmtMiB(summary.validation.vulnerable_median)}</div><div class="label">vulnerable median</div></div>
            <div class="kpi"><div class="value">${fmtMiB(summary.validation.patched_median)}</div><div class="label">patched median</div></div>
          </div>
          <dl class="kv">
            <dt>Verdict</dt><dd>${verdictBadge(summary.verdict)}</dd>
            <dt>Detection</dt><dd>${detectionBadge(summary.detection)}</dd>
            <dt>Runs</dt><dd>${dash(summary.validation.runs)}</dd>
            <dt>Finished</dt><dd>${fmtDate(summary.validation.finished_at)}</dd>
            <dt>Git commit</dt><dd class="mono">${dash(summary.git_commit)}</dd>
            <dt>Worktree</dt><dd>${summary.git_dirty === true ? badge("dirty", "warn") : summary.git_dirty === false ? badge("clean", "ok") : badge("unknown", "neutral")}</dd>
          </dl>
          <p class="muted" style="margin-top:12px">${esc(summary.validation.reason || "")}</p>
        </section>
      </div>

      <section class="card" style="margin-top:16px">
        <div class="card-head"><h2>Integrity checks</h2></div>
        ${healthList(detail.health)}
      </section>

      <div class="grid two" style="margin-top:16px">
        <section class="card">
          <div class="card-head"><h2>Exploitability</h2></div>
          <dl class="kv">
            <dt>I / E / R / D</dt><dd>${dash(exploit.impact_I)} / ${dash(exploit.exploit_E)} / ${dash(exploit.reach_R)} / ${dash(exploit.detect_D)}</dd>
            <dt>Priority</dt><dd>${dash(exploit.priority_P)}</dd>
            <dt>Tier</dt><dd>${dash(exploit.exploit_tier)}</dd>
            <dt>Impact</dt><dd>${dash(exploit.impact)}</dd>
          </dl>
          ${(exploit.prerequisites || []).length ? `<h3 style="margin-top:14px">Prerequisites</h3><ul>${exploit.prerequisites.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>` : ""}
          ${(exploit.attacker_controlled || []).length ? `<h3>Attacker control</h3><ul>${exploit.attacker_controlled.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>` : ""}
          ${exploit.notes ? `<p class="muted">${esc(exploit.notes)}</p>` : ""}
        </section>

        <section class="card">
          <div class="card-head"><h2>Catalog values</h2></div>
          <dl class="kv">
            <dt>Track</dt><dd>${dash(catalog.track)}</dd>
            <dt>Affected</dt><dd class="mono">${dash(catalog.affected)}</dd>
            <dt>Fixed in</dt><dd class="mono">${dash(catalog.fixed_in)}</dd>
            <dt>CVSS</dt><dd>${dash(catalog.cvss)}</dd>
            <dt>Published</dt><dd>${dash(catalog.published)}</dd>
            <dt>Commits</dt><dd class="mono">${(catalog.commits || []).map((commit) => esc(commit.slice(0, 12))).join("<br>") || "—"}</dd>
          </dl>
        </section>
      </div>

      <section class="card" style="margin-top:16px">
        <div class="card-head"><h2>Analysis notes</h2></div>
        <details><summary>Root cause</summary>${md(rootCause)}</details>
        <details style="margin-top:10px"><summary>Attack surface</summary>${md(attackSurface)}</details>
      </section>`;
  }

  function cveValidation(detail) {
    const validation = detail.validation;
    if (!validation) {
      return `<section class="card"><div class="empty">Validation has not been run for this package.</div>
        <div class="actions" style="margin-top:12px">
          ${actionButton("lab_start", detail.summary.cve, "Start lab")}
          ${actionButton("validate", detail.summary.cve, "Run validation")}
        </div></section>`;
    }
    const targets = validation.targets || {};
    const globalMax = Math.max(
      ...["vulnerable", "patched"].flatMap((role) => {
        const target = targets[role] || {};
        return [Number(target.summary?.max || 0), Number(target.summary?.median || 0)];
      }),
      1
    );
    const rows = ["vulnerable", "patched"].map((role) => {
      const target = targets[role] || {};
      const summary = target.summary || {};
      return `<tr>
        <td>${esc(role)}</td>
        <td class="mono">${esc(target.version || "")}</td>
        <td class="num">${fmtMiB(summary.median)}</td>
        <td class="num">${fmtMiB(summary.min)}</td>
        <td class="num">${fmtMiB(summary.max)}</td>
        <td class="num">${summary.cv == null ? "—" : `${(Number(summary.cv) * 100).toFixed(2)}%`}</td>
        <td class="num">${dash(summary.count)}</td>
      </tr>`;
    }).join("");
    const ranges = ["vulnerable", "patched"].map((role) => {
      const target = targets[role] || {};
      const summary = target.summary || {};
      const min = Number(summary.min || 0);
      const max = Number(summary.max || 0);
      const median = Number(summary.median || 0);
      const left = (min / globalMax) * 100;
      const width = Math.max(((max - min) / globalMax) * 100, 0.8);
      const medianLeft = (median / globalMax) * 100;
      return `<div class="range">
        <div class="range-label"><span>${esc(role)}</span><span>${fmtMiB(min)} – ${fmtMiB(max)}</span></div>
        <div class="range-track" title="median ${fmtMiB(median)}">
          <span class="range-fill" style="left:${left.toFixed(2)}%;width:${width.toFixed(2)}%"></span>
          <span style="position:absolute;left:${medianLeft.toFixed(2)}%;top:-3px;bottom:-3px;width:2px;background:#fff"></span>
        </div>
      </div>`;
    }).join("");
    const runs = ["vulnerable", "patched"].map((role) => {
      const target = targets[role] || {};
      const metrics = target.metrics || [];
      return `<tr><td>${esc(role)}</td>${metrics.map((value) => `<td class="num">${fmtMiB(value)}</td>`).join("")}</tr>`;
    }).join("");
    const runCount = Math.max(
      ...["vulnerable", "patched"].map((role) => (targets[role]?.metrics || []).length),
      0
    );
    return `
      <section class="card">
        <div class="card-head"><h2>Validation result</h2>${verdictBadge(validation.verdict)}</div>
        <p class="muted">${esc(validation.reason || "")}</p>
        <div class="table-wrap"><table>
          <thead><tr><th>Role</th><th>Version</th><th class="num">Median</th><th class="num">Min</th><th class="num">Max</th><th class="num">CV</th><th class="num">Runs</th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>
        <div style="margin-top:16px">${ranges}</div>
      </section>

      <section class="card" style="margin-top:16px">
        <div class="card-head"><h2>Run range</h2><span class="muted">bars start at zero; white marker is the median</span></div>
        <div class="table-wrap"><table>
          <thead><tr><th>Role</th>${Array.from({ length: runCount }, (_, index) => `<th class="num">Run ${index + 1}</th>`).join("")}</tr></thead>
          <tbody>${runs}</tbody>
        </table></div>
      </section>

      <section class="card" style="margin-top:16px">
        <div class="card-head"><h2>Images</h2></div>
        <div class="table-wrap"><table>
          <thead><tr><th>Role</th><th>Tag</th><th>Digest</th></tr></thead>
          <tbody>${Object.entries(validation.image_digests || {}).map(([role, image]) => `<tr>
            <td>${esc(role)}</td><td class="mono">${dash(image.tag)}</td><td class="mono">${dash(image.id)}</td>
          </tr>`).join("")}</tbody>
        </table></div>
      </section>`;
  }

  function cveDetection(detail) {
    const detection = detail.detection;
    if (!detection) {
      return `<section class="card"><div class="empty">Detection has not been run for this package.</div>
        <div class="actions" style="margin-top:12px">
          ${actionButton("validate", detail.summary.cve, "Run validation")}
          ${actionButton("detect", detail.summary.cve, "Run detection")}
        </div></section>`;
    }
    const targets = detection.targets || {};
    const roleTables = ["vulnerable", "patched"].map((role) => {
      const target = targets[role] || {};
      const rules = target.rules || [];
      return `<section class="card" style="margin-top:16px">
        <div class="card-head"><h2>${esc(role)}</h2>${detectionBadge(target.result)}</div>
        <div class="table-wrap"><table>
          <thead><tr><th>Rule</th><th>Triggered</th><th>Expected</th><th>Detail</th></tr></thead>
          <tbody>${rules.map((rule) => `<tr>
            <td class="mono">${esc(rule.id)}</td>
            <td>${rule.triggered ? badge("yes", "bad") : badge("no", "ok")}</td>
            <td>${badge(rule.expected || "unknown", "neutral")}</td>
            <td class="mono">${esc(rule.detail)}</td>
          </tr>`).join("")}</tbody>
        </table></div>
      </section>`;
    }).join("");
    const spec = detail.detection_spec || {};
    const specRows = (spec.rules || []).map((rule) => `<tr>
      <td class="mono">${esc(rule.id)}</td>
      <td class="mono">${esc(JSON.stringify(rule.threshold || {}))}</td>
      <td>${badge(rule.expected?.vulnerable || "unknown", "neutral")}</td>
      <td>${badge(rule.expected?.patched || "unknown", "neutral")}</td>
    </tr>`).join("");
    return `
      <section class="card">
        <div class="card-head"><h2>Overall</h2>${detectionBadge(detection.result)}</div>
        <p class="muted">${esc(detection.reason || "")}</p>
      </section>
      ${roleTables}
      <section class="card" style="margin-top:16px">
        <div class="card-head"><h2>Pre-registered thresholds</h2></div>
        <div class="table-wrap"><table>
          <thead><tr><th>Rule</th><th>Threshold</th><th>Expected vulnerable</th><th>Expected patched</th></tr></thead>
          <tbody>${specRows}</tbody>
        </table></div>
      </section>`;
  }

  function cveEvidence(detail) {
    const provenance = detail.provenance || {};
    const build = provenance.build || {};
    const execution = detail.execution || {};
    const images = Object.entries(provenance.images || {});
    return `
      <div class="grid two">
        <section class="card">
          <div class="card-head"><h2>Provenance</h2>${build.git?.dirty === true ? badge("dirty worktree", "warn") : build.git?.dirty === false ? badge("clean worktree", "ok") : badge("unknown", "neutral")}</div>
          <dl class="kv">
            <dt>Generated</dt><dd>${fmtDate(provenance.generated_at)}</dd>
            <dt>Git commit</dt><dd class="mono">${dash(build.git?.commit)}</dd>
            <dt>Base image</dt><dd class="mono">${dash(build.base_image)}</dd>
            <dt>Dockerfile</dt><dd class="mono">${esc(build.dockerfile?.path || "")} ${build.dockerfile?.sha256 ? `(${esc(build.dockerfile.sha256)})` : ""}</dd>
            <dt>Runtime</dt><dd>${provenance.runtime ? badge("recorded", "ok") : badge("missing", "warn")}</dd>
          </dl>
          ${Object.entries(build.lockfiles || {}).map(([version, lock]) => `<p class="mono muted" style="margin-top:8px">lock ${esc(version)}: ${esc(lock.path)} (${esc(lock.sha256)})</p>`).join("")}
        </section>

        <section class="card">
          <div class="card-head"><h2>Reports</h2></div>
          <div class="stack">
            <a class="btn" href="/api/packages/${encodeURIComponent(detail.summary.cve)}/report.md" download>Download report.md</a>
            <a class="btn" href="/api/packages/${encodeURIComponent(detail.summary.cve)}/report.json" download>Download report.json</a>
            <a class="btn" href="${cveHref(detail.summary.cve, "report")}">Open rendered report</a>
          </div>
          <div class="card-head" style="margin-top:20px"><h2>Images</h2></div>
          <div class="table-wrap"><table>
            <thead><tr><th>Role</th><th>Tag</th><th>ID</th></tr></thead>
            <tbody>${images.map(([role, image]) => `<tr><td>${esc(role)}</td><td class="mono">${dash(image.tag)}</td><td class="mono">${dash(image.id)}</td></tr>`).join("") || `<tr><td colspan="3" class="muted">No images recorded.</td></tr>`}</tbody>
          </table></div>
        </section>
      </div>

      <section class="card" style="margin-top:16px">
        <div class="card-head"><h2>Evidence artifacts</h2><span class="muted">${(execution.artifacts || []).length} files</span></div>
        <p class="muted">Command: <span class="mono">${esc((execution.command || []).join(" "))}</span></p>
        <div class="table-wrap"><table>
          <thead><tr><th>Path</th><th>SHA-256</th></tr></thead>
          <tbody>${(execution.artifacts || []).map((artifact) => `<tr><td class="mono">${esc(artifact.path)}</td><td class="mono">${esc(artifact.sha256)}</td></tr>`).join("") || `<tr><td colspan="2" class="muted">No evidence artifacts.</td></tr>`}</tbody>
        </table></div>
      </section>

      <section class="card" style="margin-top:16px">
        <div class="card-head"><h2>Integrity checks</h2></div>
        ${healthList(detail.health)}
      </section>`;
  }

  async function loadReport(cve) {
    const holder = document.getElementById("report-body");
    if (!holder) return;
    try {
      const text = await apiText(`/api/packages/${encodeURIComponent(cve)}/report.md`);
      holder.className = "";
      holder.innerHTML = md(text);
    } catch (error) {
      holder.innerHTML = empty(`Could not load report: ${error.message}`);
    }
  }

  // -- labs -------------------------------------------------------------

  async function renderLabs() {
    const [labs] = await Promise.all([api("/api/labs"), ensurePortfolio()]);
    const docker = state.actions.find((item) => item.id === "lab_build");
    const cards = labs.map((lab) => {
      const pkg = (state.portfolio?.packages || []).find((item) => item.cve === lab.cve);
      const services = Object.entries(lab.services || {}).map(([role, service]) => `
        <tr>
          <td>${esc(role)}</td>
          <td class="mono">${esc(service.version || "")}</td>
          <td>${service.running === undefined ? badge("unknown", "neutral") : service.running ? badge("running", "ok") : badge("stopped", "neutral")}</td>
          <td>${service.healthy === undefined ? "—" : service.healthy ? badge("healthy", "ok") : badge("unhealthy", "bad")}</td>
          <td class="mono">${esc(service.base_url || "")}</td>
          <td class="mono">${esc(service.admin_url || "")}</td>
        </tr>`).join("");
      return `<section class="card">
        <div class="card-head"><h2 class="mono">${esc(lab.cve)}</h2>${lab.running ? badge("running", "ok") : badge("stopped", "neutral")}</div>
        <dl class="kv">
          <dt>Lab</dt><dd class="mono">${dash(lab.lab_id)}</dd>
          <dt>Runtime file</dt><dd>${lab.configured ? badge("present", "ok") : badge("missing", "neutral")}</dd>
          <dt>Created</dt><dd>${fmtDate(lab.created_at)}</dd>
        </dl>
        ${lab.error ? `<div class="callout bad">${esc(lab.error)}</div>` : ""}
        ${services ? `<div class="table-wrap" style="margin-top:12px"><table>
          <thead><tr><th>Role</th><th>Version</th><th>Container</th><th>Health</th><th>App URL</th><th>Admin URL</th></tr></thead>
          <tbody>${services}</tbody>
        </table></div>` : empty("No runtime services recorded.")}
        <div class="next-action-row">${pkg ? nextAction(pkg) : ""}</div>
        <div class="actions" style="margin-top:14px">
          ${actionButton("lab_build", lab.cve, "Build")}
          ${actionButton("lab_start", lab.cve, "Start")}
          ${actionButton("lab_stop", lab.cve, "Stop")}
          ${actionButton("poc_run", lab.cve, "Run PoC")}
          ${actionButton("validate", lab.cve, "Validate")}
        </div>
      </section>`;
    }).join("");
    main.innerHTML = `
      <div class="page-head">
        <div><div class="eyebrow">Labs</div><h1>Local lab lifecycle</h1><p>Loopback-only containers. Actions run one at a time and stream into Activity.</p></div>
        <div class="actions"><button class="btn small" data-action="refresh-labs">Refresh</button></div>
      </div>
      ${docker && !docker.enabled ? `<div class="callout warn">${esc(docker.disabled_reason)}</div>` : ""}
      <div class="grid two">${cards || empty("No packages configured.")}</div>`;
  }

  // -- matrix -----------------------------------------------------------

  async function renderMatrix() {
    const [rows] = await Promise.all([ensureMatrix(), ensurePortfolio()]);
    const packaged = new Set((state.portfolio?.packages || []).map((pkg) => pkg.cve));
    const sorted = [...rows].sort((a, b) => {
      const key = state.matrixSort.key;
      const dir = state.matrixSort.dir;
      const left = a[key];
      const right = b[key];
      if (typeof left === "number" || typeof right === "number") {
        return (Number(left || 0) - Number(right || 0)) * dir;
      }
      return String(left || "").localeCompare(String(right || "")) * dir;
    });
    const header = (key, label, numeric = false) => {
      const marker = state.matrixSort.key === key ? (state.matrixSort.dir > 0 ? " ▲" : " ▼") : "";
      return `<th class="${numeric ? "num" : ""}"><button class="btn small" style="padding:2px 4px;background:none;border:0" data-action="sort-matrix" data-sort="${esc(key)}">${esc(label)}${marker}</button></th>`;
    };
    main.innerHTML = `
      <div class="page-head">
        <div><div class="eyebrow">Priority</div><h1>Research matrix</h1><p>${rows.length} advisories. Priority is independent of CVSS.</p></div>
        <div class="actions"><button class="btn small" data-action="refresh-matrix">Refresh</button></div>
      </div>
      <section class="card">
        <div class="table-wrap"><table>
          <thead><tr>
            ${header("cve", "CVE")}
            ${header("title", "Title")}
            ${header("cvss", "CVSS", true)}
            ${header("track", "Track")}
            ${header("impact_I", "I", true)}
            ${header("exploit_E", "E", true)}
            ${header("reach_R", "R", true)}
            ${header("detect_D", "D", true)}
            ${header("priority_P", "Priority", true)}
            ${header("exploit_tier", "Tier")}
            <th>Package</th>
          </tr></thead>
          <tbody>${sorted.map((row) => `<tr>
            <td class="mono">${packaged.has(row.cve) ? `<a href="${cveHref(row.cve)}">${esc(row.cve)}</a>` : esc(row.cve)}</td>
            <td>${esc(row.title)}</td>
            <td class="num">${fmtNumber(row.cvss, 1)}</td>
            <td>${esc(row.track)}</td>
            <td class="num">${dash(row.impact_I)}</td>
            <td class="num">${dash(row.exploit_E)}</td>
            <td class="num">${dash(row.reach_R)}</td>
            <td class="num">${dash(row.detect_D)}</td>
            <td class="num">${fmtNumber(row.priority_P)}</td>
            <td>${esc(row.exploit_tier)}</td>
            <td>${packaged.has(row.cve) ? badge("packaged", "ok") : badge("not packaged", "neutral")}</td>
          </tr>`).join("")}</tbody>
        </table></div>
      </section>`;
  }

  // -- activity ---------------------------------------------------------

  function jobStatus(job) {
    return `<span class="job-status ${esc(job.status)}">${esc(job.status)}</span>`;
  }

  function renderActivityFromState() {
    const jobs = state.jobs;
    main.innerHTML = `
      <div class="page-head">
        <div><div class="eyebrow">Actions</div><h1>Activity</h1><p>One job runs at a time. Logs stream from the real CLI invocation.</p></div>
        <div class="actions">
          <button class="btn small" data-action="refresh-jobs">Refresh</button>
          ${actionButton("package_validate", "", "Check packages")}
          ${actionButton("triage_check", "", "Check triage")}
        </div>
      </div>
      <section class="card">
        ${jobs.length ? `<div class="table-wrap"><table>
          <thead><tr><th>When</th><th>Action</th><th>CVE</th><th>Status</th><th>Result</th><th>Last line</th><th></th></tr></thead>
          <tbody>${jobs.map((job) => `<tr>
            <td class="nowrap">${fmtDate(job.created_at)}</td>
            <td>${esc(job.label)}</td>
            <td class="mono">${dash(job.cve)}</td>
            <td>${jobStatus(job)}</td>
            <td class="num">${job.returncode == null ? "—" : esc(job.returncode)}</td>
            <td class="mono muted">${job.last_line ? esc(job.last_line) : "—"}</td>
            <td><button class="btn small" data-action="open-job" data-id="${esc(job.id)}">Logs</button></td>
          </tr>`).join("")}</tbody>
        </table></div>` : empty("No jobs yet.")}
      </section>`;
  }

  async function renderActivity() {
    state.jobs = await api("/api/jobs");
    renderActivityFromState();
    schedulePolling();
  }

  function schedulePolling() {
    if (state.poll) clearInterval(state.poll);
    const hasActive = state.jobs.some((job) => ["queued", "running"].includes(job.status));
    if (!hasActive) return;
    state.poll = setInterval(async () => {
      try {
        state.jobs = await api("/api/jobs");
        if (state.modalOpen && state.modalJobId) {
          await updateJobModal();
        } else if (activePage() === "activity") {
          renderActivityFromState();
        }
        if (!state.jobs.some((job) => ["queued", "running"].includes(job.status))) {
          clearInterval(state.poll);
          state.poll = null;
        }
      } catch (error) {
        clearInterval(state.poll);
        state.poll = null;
        toast(error.message, true);
      }
    }, 900);
  }

  async function openJobModal(jobId) {
    state.modalJobId = jobId;
    state.modalOpen = true;
    modalTitle.textContent = "Job log";
    modalBody.innerHTML = '<div class="loading">Loading…</div>';
    modal.hidden = false;
    await updateJobModal();
  }

  async function updateJobModal() {
    if (!state.modalJobId) return;
    try {
      const job = await api(`/api/jobs/${encodeURIComponent(state.modalJobId)}`);
      modalTitle.textContent = `${job.label}${job.cve ? ` · ${job.cve}` : ""}`;
      modalBody.innerHTML = `
        <dl class="kv">
          <dt>Status</dt><dd>${jobStatus(job)}</dd>
          <dt>Command</dt><dd class="mono">${esc(job.command)}</dd>
          <dt>Started</dt><dd>${fmtDate(job.started_at)}</dd>
          <dt>Finished</dt><dd>${fmtDate(job.finished_at)}</dd>
          <dt>Exit code</dt><dd>${job.returncode == null ? "—" : esc(job.returncode)}</dd>
        </dl>
        <pre class="log" id="job-log">${esc(job.log.join("\n"))}</pre>`;
      const log = document.getElementById("job-log");
      if (log) log.scrollTop = log.scrollHeight;
    } catch (error) {
      modalBody.innerHTML = `<div class="callout bad">${esc(error.message)}</div>`;
    }
  }

  // -- doctor -----------------------------------------------------------

  async function renderDoctor() {
    const checks = await api("/api/doctor");
    main.innerHTML = `
      <div class="page-head">
        <div><div class="eyebrow">Environment</div><h1>Health</h1><p>Checks used by <code>vulnforge doctor</code>.</p></div>
        <div class="actions"><button class="btn small" data-action="refresh-doctor">Refresh</button></div>
      </div>
      <section class="card">
        <div class="table-wrap"><table>
          <thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
          <tbody>${checks.map((check) => `<tr>
            <td>${esc(check.name)}</td>
            <td>${check.ok ? badge("OK", "ok") : badge("FAIL", "bad")}</td>
            <td class="mono">${esc(check.detail)}</td>
          </tr>`).join("")}</tbody>
        </table></div>
      </section>`;
  }

  // -- action modal -----------------------------------------------------

  function closeModal() {
    modal.hidden = true;
    state.modalOpen = false;
    state.modalJobId = null;
    modalBody.innerHTML = "";
  }

  function openActionModal(actionId, cve) {
    const action = state.actions.find((item) => item.id === actionId);
    if (!action) return;
    if (!action.enabled) { toast(action.disabled_reason || "Action disabled", true); return; }
    const readiness = actionReadiness(actionId, cve);
    if (readiness && !readiness.enabled) {
      toast(readiness.reason || "Action is not ready", true);
      return;
    }
    state.modalOpen = true;
    state.modalJobId = null;
    modalTitle.textContent = action.label;

    const cveOptions = (action.known_cves || []).map((name) => `<option value="${esc(name)}" ${name === cve ? "selected" : ""}>${esc(name)}</option>`).join("");
    const cveField = action.cve_allowed ? `
      <div class="field">
        <label for="action-cve">CVE</label>
        <select id="action-cve" name="cve" ${action.cve_required ? "required" : ""}>
          ${action.cve_required ? "" : `<option value="" ${cve ? "" : "selected"}>— all packages —</option>`}
          ${cveOptions}
        </select>
      </div>` : "";
    const optionFields = Object.entries(action.options || {}).map(([name, meta]) => {
      if (meta.type === "enum") {
        return `<div class="field">
          <label for="option-${esc(name)}">${esc(meta.label || name)}</label>
          <select id="option-${esc(name)}" name="option-${esc(name)}">
            ${(meta.choices || []).map((choice) => `<option value="${esc(choice)}" ${choice === meta.default ? "selected" : ""}>${esc(choice)}</option>`).join("")}
          </select>
        </div>`;
      }
      if (meta.type === "text") {
        return `<div class="field">
          <label for="option-${esc(name)}">${esc(meta.label || name)}</label>
          <input id="option-${esc(name)}" name="option-${esc(name)}" type="text" value="${meta.default == null ? "" : esc(meta.default)}">
          ${meta.help ? `<span class="hint">${esc(meta.help)}</span>` : ""}
        </div>`;
      }
      if (meta.type === "bool") {
        return `<div class="field">
          <label><input id="option-${esc(name)}" name="option-${esc(name)}" type="checkbox" ${meta.default ? "checked" : ""}> ${esc(meta.label || name)}</label>
          ${meta.help ? `<span class="hint">${esc(meta.help)}</span>` : ""}
        </div>`;
      }
      return `<div class="field">
        <label for="option-${esc(name)}">${esc(meta.label || name)}</label>
        <input id="option-${esc(name)}" name="option-${esc(name)}" type="number" min="${esc(meta.min)}" max="${esc(meta.max)}" value="${meta.default == null ? "" : esc(meta.default)}">
        ${meta.help ? `<span class="hint">${esc(meta.help)}</span>` : ""}
      </div>`;
    }).join("");
    const writes = (action.writes || []).length
      ? `<div class="callout"><strong>Writes:</strong> ${action.writes.map((item) => `<code>${esc(item)}</code>`).join(" ")}</div>`
      : "";
    const destructive = action.destructive
      ? `<div class="callout bad"><strong>Destructive:</strong> this stops and removes the lab containers and network.</div>
         <div class="field"><label><input type="checkbox" name="confirm" required> I understand this will remove the lab runtime.</label></div>`
      : "";
    modalBody.innerHTML = `
      <p class="muted">${esc(action.description)}</p>
      <form id="action-form" data-action-id="${esc(action.id)}">
        ${cveField}
        ${optionFields}
        ${writes}
        ${destructive}
        <div class="actions" style="margin-top:16px">
          <button class="btn primary" type="submit">Run ${esc(action.label)}</button>
          <button class="btn" type="button" data-close-modal>Cancel</button>
        </div>
      </form>`;
    modal.hidden = false;
    const form = document.getElementById("action-form");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(form);
      const options = {};
      Object.keys(action.options || {}).forEach((name) => {
        const value = data.get(`option-${name}`);
        if (value !== null && value !== "") options[name] = value;
      });
      const selectedCve = data.get("cve");
      try {
        const job = await submitAction(action.id, selectedCve || null, options);
        closeModal();
        toast(`Queued ${action.label}${job.cve ? ` for ${job.cve}` : ""}`);
        state.jobs = await api("/api/jobs");
        if (activePage() === "activity") renderActivityFromState();
        else location.hash = "#/activity";
        schedulePolling();
      } catch (error) {
        toast(error.message, true);
      }
    });
  }

  async function submitAction(actionId, cve, options) {
    return api("/api/jobs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-VulnForge-CSRF": state.session.csrf_token,
      },
      body: JSON.stringify({ action: actionId, cve, options }),
    });
  }

  // -- events -----------------------------------------------------------

  document.addEventListener("click", async (event) => {
    if (event.target.closest("[data-close-modal]") || event.target === modal) {
      closeModal();
      return;
    }
    const sortButton = event.target.closest("[data-sort]");
    if (sortButton) {
      const key = sortButton.dataset.sort;
      if (state.matrixSort.key === key) state.matrixSort.dir *= -1;
      else state.matrixSort = { key, dir: key === "title" || key === "cve" || key === "track" || key === "exploit_tier" ? 1 : -1 };
      state.matrix = null;
      await renderMatrix();
      return;
    }
    const button = event.target.closest("[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    if (action === "open-action") {
      event.preventDefault();
      openActionModal(button.dataset.id, button.dataset.cve || null);
    } else if (action === "open-job") {
      event.preventDefault();
      await openJobModal(button.dataset.id);
    } else if (action === "refresh-overview" || action === "refresh-packages" || action === "refresh-matrix") {
      state.portfolio = null;
      state.matrix = null;
      await route();
    } else if (action === "refresh-labs") {
      await renderLabs();
    } else if (action === "refresh-jobs") {
      await renderActivity();
    } else if (action === "refresh-doctor") {
      await renderDoctor();
    } else if (action === "refresh-detail") {
      state.detail = null;
      await renderCve(button.dataset.cve, button.dataset.tab || "overview");
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && state.modalOpen) closeModal();
  });

  // -- init -------------------------------------------------------------

  async function init() {
    try {
      state.session = await api("/api/session");
      const indicator = document.getElementById("mode-indicator");
      indicator.textContent = state.session.read_only ? "read-only" : "actions enabled";
      indicator.className = `mode ${state.session.read_only ? "readonly" : "live"}`;
      document.getElementById("root-path").textContent = state.session.root;
      state.actions = await api("/api/actions");
    } catch (error) {
      main.innerHTML = `<div class="card"><h1>VulnForge UI unavailable</h1><p class="muted">${esc(error.message)}</p></div>`;
      return;
    }
    window.addEventListener("hashchange", route);
    if (!location.hash) history.replaceState(null, "", "#/overview");
    await route();
  }

  init();
})();
