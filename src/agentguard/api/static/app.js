"use strict";
// Dashboard for the AgentGuard API. All server data is rendered with textContent only.
(function () {
  const $ = (id) => document.getElementById(id);

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function headers() {
    const h = { "Content-Type": "application/json" };
    const key = $("apikey").value.trim();
    if (key) h["X-API-Key"] = key;
    return h;
  }

  async function api(path, options) {
    const res = await fetch(path, Object.assign({ headers: headers() }, options || {}));
    const ctype = res.headers.get("content-type") || "";
    const body = ctype.includes("json") ? await res.json() : await res.text();
    if (!res.ok) {
      let detail = body && body.detail !== undefined ? body.detail : body;
      if (Array.isArray(detail)) detail = detail.map((d) => d.msg || JSON.stringify(d)).join("; ");
      throw new Error(res.status + ": " + (typeof detail === "string" ? detail : JSON.stringify(detail)));
    }
    return body;
  }

  const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body || {}) });
  const setStatus = (t) => { $("status").textContent = t; };

  function verdictBadge(v) { return el("span", "verdict v-" + v, v.replace("_", " ")); }

  function decisionCard(out) {
    const d = out.decision;
    const card = el("div", "card");
    const head = el("div");
    head.append(verdictBadge(d.verdict), el("span", "small", "  risk " + d.risk_score + "/100 · policy " + out.policy + (d.rule ? " · rule " + d.rule : "")));
    card.append(head);
    const reasons = el("ul");
    (d.reasons || []).forEach((r) => reasons.append(el("li", null, r)));
    card.append(reasons);
    if (d.findings && d.findings.length) {
      card.append(el("p", "small", "Findings"));
      const f = el("ul");
      d.findings.forEach((x) => f.append(el("li", null, "[" + x.severity + "] " + x.code + " - " + x.message)));
      card.append(f);
    }
    if (d.redacted_text) { card.append(el("p", "small", "Redacted text"), el("pre", null, d.redacted_text)); }
    if (d.redacted_arguments) { card.append(el("p", "small", "Redacted arguments"), el("pre", null, JSON.stringify(d.redacted_arguments, null, 2))); }
    if (out.approval_id) card.append(el("p", "small", "Queued for human approval: " + out.approval_id));
    return card;
  }

  function show(node) { const r = $("result"); r.replaceChildren(node); }

  async function busy(btn, fn) {
    btn.disabled = true; setStatus("");
    try { await fn(); } catch (err) { setStatus(err.message); } finally { btn.disabled = false; }
  }

  async function scan() {
    const out = await post("/api/scan", { text: $("text").value, mode: $("scanmode").value, policy: $("policy").value });
    show(decisionCard(out)); refreshAudit();
  }

  async function check() {
    let args;
    try { args = JSON.parse($("args").value || "{}"); } catch (e) { throw new Error("arguments must be valid JSON"); }
    const call = { tool: $("tool").value.trim(), agent: $("agent").value.trim() || "assistant", arguments: args, cost: Number($("cost").value) || 0 };
    const out = await post("/api/guard/tool-call", { call: call, policy: $("policy").value });
    show(decisionCard(out)); refreshApprovals(); refreshAudit();
  }

  async function runScenario() {
    const out = await post("/api/scenarios/" + encodeURIComponent($("scenario").value) + "/run");
    const box = $("timeline");
    box.replaceChildren();
    const summary = el("p", out.meets_expectations ? "good" : "bad",
      "blocked " + out.blocked + " · approvals " + out.approvals + " · executed " + out.executed +
      " · expectations " + (out.meets_expectations ? "met" : "NOT met") + " · policy " + out.policy);
    const list = el("ul", "list");
    out.steps.forEach((st) => {
      const v = st.decision ? st.decision.verdict : "deny";
      const li = el("li", "k-" + v);
      const top = el("div");
      if (st.decision) top.append(verdictBadge(v), el("span", "small", "  risk " + st.decision.risk_score + " · "));
      top.append(el("strong", null, st.kind === "tool_call" ? "tool " + st.tool : st.kind));
      li.append(top);
      li.append(el("div", "mono", st.kind === "tool_call" ? JSON.stringify(st.arguments) : st.detail));
      if (st.decision && st.decision.verdict !== "allow") li.append(el("div", "small", (st.decision.reasons || []).join("; ")));
      list.append(li);
    });
    box.append(summary, list, el("p", "small", "Final answer: " + (out.final || "(none)")));
    refreshAudit();
  }

  async function resolve(id, approve) {
    try {
      await post("/api/approvals/" + encodeURIComponent(id) + "/" + (approve ? "approve" : "deny"), { reviewer: "dashboard" });
    } catch (err) { setStatus(err.message); }
    refreshApprovals(); refreshAudit();
  }

  async function refreshApprovals() {
    let out;
    try { out = await api("/api/approvals"); } catch (err) { return; }
    const ul = $("approvals");
    ul.replaceChildren();
    if (!out.approvals.length) { ul.append(el("li", null, "No approvals yet - check a risky tool call (e.g. refund above the limit).")); return; }
    out.approvals.forEach((a) => {
      const li = el("li", a.status === "pending" ? "k-require_approval" : (a.status === "approved" ? "k-allow" : "k-deny"));
      li.append(el("strong", null, a.id + " · " + a.call.tool + " · " + a.status + (a.reviewer ? " by " + a.reviewer : "")));
      li.append(el("div", "mono", JSON.stringify(a.call.arguments)));
      li.append(el("div", "small", (a.decision.reasons || []).join("; ")));
      if (a.status === "pending") {
        const row = el("div", "row");
        const ok = el("button", "ok", "Approve"); ok.addEventListener("click", () => resolve(a.id, true));
        const no = el("button", "no", "Deny"); no.addEventListener("click", () => resolve(a.id, false));
        row.append(ok, no); li.append(row);
      }
      ul.append(li);
    });
  }

  async function refreshAudit() {
    let log, chain;
    try { [log, chain] = await Promise.all([api("/api/audit?limit=30"), api("/api/audit/verify")]); } catch (err) { return; }
    const c = $("chain");
    c.className = chain.ok ? "small good" : "small bad";
    c.textContent = (chain.ok ? "Hash chain intact" : "Hash chain BROKEN: " + chain.error) + " · " + chain.records + " records · head " + chain.head.slice(0, 16);
    const ul = $("audit");
    ul.replaceChildren();
    log.records.forEach((r) => {
      const v = (r.data && r.data.verdict) || "";
      const li = el("li", v ? "k-" + v : null);
      li.textContent = "#" + r.index + " " + r.ts + " " + r.event + (v ? " -> " + v : "") +
        (r.data && r.data.tool ? " (" + r.data.tool + ")" : "") + "  hash " + String(r.hash).slice(0, 12) + " prev " + String(r.prev_hash).slice(0, 12);
      ul.append(li);
    });
  }

  function fill(select, items) {
    select.replaceChildren();
    items.forEach(([value, label]) => { const o = el("option", null, label); o.value = value; select.append(o); });
  }

  async function init() {
    let cfg;
    try { cfg = await api("/api/config"); } catch (err) { setStatus(err.message); return; }
    $("mode").textContent = cfg.access_mode + " · provider " + cfg.provider + " · v" + cfg.version;
    fill($("policy"), cfg.policies.map((p) => [p, p]));
    try {
      const sc = await api("/api/scenarios");
      fill($("scenario"), sc.scenarios.map((s) => [s.id, s.title]));
    } catch (err) { setStatus(err.message); }
    refreshApprovals(); refreshAudit();
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("scan").addEventListener("click", (e) => busy(e.target, scan));
    $("check").addEventListener("click", (e) => busy(e.target, check));
    $("run").addEventListener("click", (e) => busy(e.target, runScenario));
    $("refresh-approvals").addEventListener("click", refreshApprovals);
    $("refresh-audit").addEventListener("click", refreshAudit);
    $("apikey").addEventListener("change", init);
    init();
  });
})();
