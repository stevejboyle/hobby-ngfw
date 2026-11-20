// SJB-OS web UI. Plain JavaScript, no build step. Everything is built with
// DOM calls (never innerHTML with data) so config text can't inject markup.
"use strict";

const state = { csrf: "", user: "", me: null, status: null, cand: null, clockSkew: 0, staged: null };

// ---- what the user's role allows ----------------------------------------------
// ngfwd checks every call; the UI only hides what the role can't use.
const can = (area, level = "view") => {
  const m = state.me || {};
  if (m.superuser) return true;
  const l = (m.permissions || {})[area];
  return l === "change" || (level === "view" && l === "view");
};
const isSuper = () => !!(state.me && state.me.superuser);
// Config sections by area (as internal/accounts maps them).
const areaOfKey = {
  zones: "policy", addresses: "policy", address_groups: "policy", services: "policy", rules: "policy", application_groups: "policy", nat: "policy",
  interfaces: "network", routes: "network", vrfs: "network", routing: "network", bgp_neighbors: "network", ospf_interfaces: "network", prefix_lists: "network",
  dhcp_servers: "dhcp", dhcp_reservations: "dhcp", ips_profiles: "ips", decryption_rules: "decryption", decryption_profiles: "decryption", decryption_exclusions: "decryption",
};
// Pages by what they need to be seen.
const pageNeeds = {
  policy: () => can("policy"), nat: () => can("policy"), objects: () => can("policy"), network: () => can("network"), routing: () => can("network"),
  dhcp: () => can("dhcp"), apps: () => can("monitoring"), ips: () => can("ips"), decryption: () => can("decryption"), tags: () => can("tags"),
  revisions: () => can("revisions"), logs: () => can("monitoring"), users: isSuper, roles: isSuper,
};
function applyNav() {
  for (const a of document.querySelectorAll("#nav a, .who a")) {
    const need = pageNeeds[a.getAttribute("href").slice(1)];
    a.classList.toggle("hidden", !!need && !need());
  }
  for (const m of document.querySelectorAll("#nav .menu")) m.classList.toggle("hidden", !m.querySelector("a:not(.hidden)"));
}

// ---- tiny DOM helper -------------------------------------------------------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const $ = (sel) => document.querySelector(sel);

// ---- API -------------------------------------------------------------------
class ApiError extends Error {
  constructor(status, body) {
    super(body.error || `HTTP ${status}`);
    this.status = status;
    this.list = body.errors || [];
  }
}

async function api(method, path, body, raw) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (method !== "GET") opts.headers["X-SJB-CSRF"] = state.csrf;
  if (raw) {
    opts.body = raw;
    opts.headers["Content-Type"] = "application/octet-stream";
  } else if (body !== undefined) {
    opts.body = JSON.stringify(body);
    opts.headers["Content-Type"] = "application/json";
  }
  const res = await fetch("/ui/api/" + path, opts);
  let data = {};
  const text = await res.text();
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text }; }
  if (res.status === 401 && path !== "login") {
    showLogin();
    throw new ApiError(401, data);
  }
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

// ---- feedback --------------------------------------------------------------
let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 4000);
}

function errorBox(err) {
  const items = err.list && err.list.length ? err.list : [err.message];
  return h("ul", { class: "errors", role: "alert" }, items.map((e) => h("li", {}, e)));
}

// Generic modal. fields: array of nodes; onSubmit returns a promise; throwing
// shows the error in the dialog and keeps it open.
function modal(title, body, { submit = "Save", onSubmit, danger = false, wide = false } = {}) {
  const dlg = $("#dialog");
  const form = $("#dialog-form");
  form.replaceChildren();
  const errs = h("div");
  const ok = submit ? h("button", { type: "submit", class: danger ? "danger" : "primary", value: "ok" }, submit) : null;
  form.append(
    h("h2", {}, title),
    body,
    errs,
    h("div", { class: "dialog-actions" },
      h("button", { type: "button", onclick: () => dlg.close() }, submit ? "Cancel" : "Close"),
      ok),
  );
  dlg.style.width = wide ? "min(900px, calc(100vw - 32px))" : "";
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    if (!onSubmit) return dlg.close();
    ok.disabled = true;
    errs.replaceChildren();
    try {
      await onSubmit();
      dlg.close();
    } catch (e) {
      errs.replaceChildren(errorBox(e));
    } finally {
      ok.disabled = false;
    }
  };
  dlg.showModal();
  const first = form.querySelector("input, select, textarea");
  if (first) first.focus();
}

function confirmDialog(title, text, action, label = "OK", danger = true) {
  modal(title, h("p", {}, text), { submit: label, danger, onSubmit: action });
}

// ---- login -----------------------------------------------------------------
function showLogin() {
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  $("#login-form").password.focus();
}

$("#login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const err = $("#login-error");
  err.classList.add("hidden");
  try {
    const s = await api("POST", "login", { user: f.user.value, password: f.password.value });
    f.password.value = "";
    await enter(s);
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove("hidden");
  }
});

$("#logout").addEventListener("click", async () => {
  try { await api("POST", "logout", {}); } catch {}
  state.csrf = "";
  showLogin();
});

async function enter(s) {
  state.csrf = s.csrf;
  state.user = s.user;
  state.me = s;
  applyNav();
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  await refresh();
  route();
}

// ---- shared state ----------------------------------------------------------
async function refresh() {
  const [st, cand] = await Promise.all([api("GET", "status"), state.me && !state.me.config_view ? {} : api("GET", "config/candidate")]);
  state.status = st;
  state.cand = normalise(cand);
  state.clockSkew = Date.parse(st.now) - Date.now();
  $("#version").textContent = st.version ? "v" + st.version : "";
  $("#host").textContent = `${state.user}@${st.hostname || "sjb-fw"}` + (state.me ? ` (${state.me.role})` : "");
  renderBars();
}

function normalise(c) {
  c = c || {};
  c.system = c.system || { hostname: "", mgmt_interface: "" };
  for (const k of ["zones", "interfaces", "addresses", "address_groups", "services", "rules", "nat", "routes", "vrfs", "routing", "bgp_neighbors", "ospf_interfaces", "prefix_lists", "dhcp_servers", "dhcp_reservations", "application_groups", "ips_profiles", "decryption_rules", "decryption_profiles", "decryption_exclusions"]) c[k] = c[k] || [];
  c.system.ips_disabled_signatures = c.system.ips_disabled_signatures || [];
  return c;
}

// Save a modified copy of the candidate. The server validates the whole
// config; on error nothing changes.
async function saveCandidate(cfg, what) {
  await api("PUT", "config/candidate", cfg);
  await refresh();
  if (what) toast(what);
  route();
}

function clone(o) { return JSON.parse(JSON.stringify(o)); }
const cap = (s) => s[0].toUpperCase() + s.slice(1);

// ---- commit bars -----------------------------------------------------------
let confirmTimer;
function renderBars() {
  const st = state.status;
  const pend = $("#pending-bar");
  if (st.recovery) {
    // Live enforcement may not match the running revision: say so first.
    pend.replaceChildren(
      h("strong", { class: "action-deny" }, "Needs attention"),
      h("span", {}, st.recovery),
      h("span", { class: "spacer" }),
      state.me.config_edit ? h("span", { class: "buttons" }, h("button", { class: "primary", onclick: commitDialog }, "Commit…")) : null,
    );
    pend.classList.remove("hidden");
  } else if (st.uncommitted_changes) {
    pend.replaceChildren(
      h("strong", {}, "Uncommitted changes"),
      h("span", {}, "Edits go to the candidate config. Nothing reaches the firewall until you commit."),
      h("span", { class: "spacer" }),
      h("span", { class: "buttons" },
        h("button", { onclick: showDiff }, "Review diff"),
        !state.me.config_edit ? null : [
        h("button", { onclick: () => confirmDialog("Discard changes?", "The candidate goes back to the running config.", async () => { await api("POST", "config/revert", {}); await refresh(); route(); toast("Changes discarded."); }, "Discard") }, "Discard"),
        h("button", { class: "primary", onclick: commitDialog }, "Commit…")]),
    );
    pend.classList.toggle("hidden", !state.me.config_view);
  } else pend.classList.add("hidden");

  clearInterval(confirmTimer);
  const bar = $("#confirm-bar");
  if (st.confirm_by) {
    const deadline = Date.parse(st.confirm_by) - state.clockSkew;
    const tick = () => {
      const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
      bar.replaceChildren(
        h("strong", {}, `Revision ${st.running_revision} rolls back in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`),
        h("span", {}, "unless you confirm it. Check the firewall still does what you expect first."),
        h("span", { class: "spacer" }),
        can("revisions", "change") ? h("button", { class: "primary", onclick: doConfirm }, "Confirm") : null,
      );
      if (left === 0) { clearInterval(confirmTimer); setTimeout(async () => { await refresh(); route(); }, 2000); }
    };
    tick();
    confirmTimer = setInterval(tick, 1000);
    bar.classList.remove("hidden");
  } else bar.classList.add("hidden");
}

async function doConfirm() {
  try {
    await api("POST", "confirm", {});
    toast("Confirmed. New rules, same vigilance.");
  } catch (e) { toast(e.message); }
  await refresh();
  route();
}

async function showDiff() {
  const [d, p] = await Promise.all([api("GET", "diff"), api("GET", "preview").catch((e) => ({ warnings: [], error: e }))]);
  const lines = (d.diff || "no changes").split("\n").map((l) =>
    h("span", { class: l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : "" }, l + "\n"));
  modal("Changes to commit", h("div", {},
    h("pre", { class: "diff block" }, lines),
    (p.warnings || []).length ? h("div", {}, h("h3", {}, "Warnings"), h("ul", {}, p.warnings.map((w) => h("li", {}, w)))) : null,
  ), { submit: null, wide: true });
}

function commitDialog() {
  const msg = h("input", { name: "message", placeholder: "What changed and why" });
  const useTimer = h("input", { type: "checkbox", checked: true });
  const mins = h("input", { type: "number", min: 1, max: 60, value: 5 });
  useTimer.addEventListener("change", () => { mins.disabled = !useTimer.checked; });
  modal("Commit", h("div", { class: "grid2" },
    h("label", {}, "Message", msg),
    h("div", {},
      h("label", { class: "check" }, useTimer, "Roll back automatically unless I confirm within"),
      h("div", { class: "row" }, h("label", {}, mins), h("span", { class: "muted" }, "minutes"))),
  ), {
    submit: "Commit",
    onSubmit: async () => {
      const res = await api("POST", "commit", { message: msg.value, confirm_minutes: useTimer.checked ? Number(mins.value) : 0 });
      await refresh();
      route();
      toast(`Revision ${res.revision.n} committed. New rules, same vigilance.`);
      if (res.warnings && res.warnings.length) {
        // Let the commit dialog close first, then show what needs attention.
        setTimeout(() => modal(`Revision ${res.revision.n} committed, with warnings`,
          h("ul", {}, res.warnings.map((w) => h("li", {}, w))), { submit: null }), 0);
      }
    },
  });
}

// ---- field widgets ---------------------------------------------------------
function textField(label, value, opts = {}) {
  const input = h("input", { value: value || "", placeholder: opts.placeholder || "", required: opts.required });
  return { node: h("label", {}, label, opts.hint ? h("span", { class: "hint" }, opts.hint) : null, input), get: () => input.value.trim() };
}

function selectField(label, value, options, opts = {}) {
  const sel = h("select", {}, options.map((o) => h("option", { value: o.value ?? o, selected: (o.value ?? o) === value }, o.label ?? o)));
  return { node: h("label", {}, label, opts.hint ? h("span", { class: "hint" }, opts.hint) : null, sel), get: () => sel.value };
}

// Multi-select with "any": empty list means any.
function multiField(label, values, options, opts = {}) {
  values = values || [];
  const anyBox = opts.noAny ? null : h("input", { type: "checkbox", checked: values.length === 0 || values.includes("any") });
  const sel = h("select", { multiple: true, "aria-label": label },
    options.map((o) => h("option", { value: o, selected: values.includes(o) }, o)));
  const sync = () => { if (anyBox) sel.disabled = anyBox.checked; };
  if (anyBox) anyBox.addEventListener("change", sync);
  sync();
  return {
    node: h("label", {}, label,
      h("span", { class: "hint" }, opts.hint || (options.length ? "Ctrl/Cmd-click to pick several" : "Nothing defined yet")),
      anyBox ? h("label", { class: "check" }, anyBox, opts.anyLabel || "any") : null,
      sel),
    get: () => (anyBox && anyBox.checked ? (opts.anyValue || []) : [...sel.selectedOptions].map((o) => o.value)),
  };
}

function checkField(label, value) {
  const box = h("input", { type: "checkbox", checked: !!value });
  return { node: h("label", { class: "check" }, box, label), get: () => box.checked };
}

function listField(label, values, hint) {
  const input = h("input", { value: (values || []).join(", "), placeholder: hint || "" });
  return {
    node: h("label", {}, label, h("span", { class: "hint" }, "Comma-separated"), input),
    get: () => input.value.split(",").map((s) => s.trim()).filter(Boolean),
  };
}

const chips = (list, anyWord = "any") =>
  !list || list.length === 0 ? h("span", { class: "chip any" }, anyWord) : list.map((x) => h("span", { class: "chip" + (x === "any" ? " any" : "") }, x));

const zoneNames = () => state.cand.zones.map((z) => z.name);
const addrNames = () => [...state.cand.addresses.map((a) => a.name), ...state.cand.address_groups.map((g) => g.name)];
const serviceNames = () => state.cand.services.map((s) => s.name);

// ---- generic list page -----------------------------------------------------
// spec: {key, title, singular, columns: [[header, row => node]], form(item) -> {node, get}, orderable}
function listSection(spec) {
  const items = state.cand[spec.key];
  const ro = !can(areaOfKey[spec.key] || "policy", "change");
  const edit = (i) => {
    const isNew = i < 0;
    const f = spec.form(isNew ? spec.blank() : clone(items[i]));
    modal(isNew ? `New ${spec.singular}` : `Edit ${spec.singular} ${items[i].name}`, f.node, {
      onSubmit: async () => {
        const cfg = clone(state.cand);
        const item = f.get();
        if (isNew) cfg[spec.key].push(item); else cfg[spec.key][i] = item;
        await saveCandidate(cfg, `${cap(spec.singular)} ${item.name} saved to the candidate.`);
      },
    });
  };
  const del = (i) => confirmDialog(`Delete ${spec.singular} ${items[i].name}?`,
    "It is removed from the candidate config. Anything that refers to it must be changed first.",
    async () => {
      const cfg = clone(state.cand);
      cfg[spec.key].splice(i, 1);
      await saveCandidate(cfg, `${cap(spec.singular)} ${items[i].name} deleted from the candidate.`);
    }, "Delete");
  // spec.filter shows part of the list (the NAT page splits one list by
  // type); moves swap with the neighbour in the same view.
  const shown = items.map((_, i) => i).filter((i) => !spec.filter || spec.filter(items[i]));
  const move = async (k, d) => {
    const cfg = clone(state.cand);
    const arr = cfg[spec.key];
    const [a, b] = [shown[k], shown[k + d]];
    [arr[a], arr[b]] = [arr[b], arr[a]];
    try { await saveCandidate(cfg, "Order changed in the candidate."); } catch (e) { toast(e.message); }
  };

  const head = h("tr", {}, spec.orderable ? h("th", { class: "num" }, "#") : null,
    spec.columns.map(([t]) => h("th", {}, t)), h("th", {}, h("span", { class: "hidden" }, "Actions")));
  const rows = shown.map((i, k) => { const it = items[i]; return h("tr", {},
    spec.orderable ? h("td", { class: "num" }, k + 1) : null,
    spec.columns.map(([, f]) => h("td", {}, f(it))),
    h("td", { class: "actions" }, ro ? null : [
      spec.orderable ? [
        h("button", { class: "icon", title: "Move up", "aria-label": `Move ${it.name} up`, disabled: k === 0, onclick: () => move(k, -1) }, "↑"),
        h("button", { class: "icon", title: "Move down", "aria-label": `Move ${it.name} down`, disabled: k === shown.length - 1, onclick: () => move(k, 1) }, "↓"),
      ] : null,
      h("button", { class: "link", onclick: () => edit(i) }, "Edit"),
      h("button", { class: "link danger", onclick: () => del(i) }, "Delete")])); });

  return h("section", { class: "panel" },
    h("div", { class: "page-head" }, h("h2", {}, spec.title), spec.note ? h("span", { class: "muted small" }, spec.note) : null,
      h("span", { class: "spacer" }), ro ? h("span", { class: "muted small" }, "view only") : h("button", { class: "primary", onclick: () => edit(-1) }, `Add ${spec.singular}`)),
    shown.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, head), h("tbody", {}, rows)))
      : h("p", { class: "empty" }, `No ${spec.title.toLowerCase()} yet.`));
}

function form(fields, build) {
  return { node: h("div", { class: "grid2" }, fields.map((f) => f.node)), get: build };
}

// ---- application picker (App Identification) --------------------------------------------
// The catalog is fetched once per page load; rules store names lower-cased.
state.appCatalog = null;
state.appCategories = [];
async function appCatalog() {
  if (!state.appCatalog) {
    try {
      [state.appCatalog, state.appCategories] = await Promise.all([api("GET", "apps/catalog"), api("GET", "apps/categories")]);
    } catch (e) { state.appCatalog = []; state.appCategories = []; }
  }
  return state.appCatalog;
}
// appLabel shows a stored (lower-case) app name as the catalog spells it.
const appLabel = (n) => {
  if (n === "unknown") return "unknown (not identified)";
  if (n.startsWith("category:")) {
    const c = (state.appCategories || []).find((x) => x.ref === n);
    return `Category: ${c ? c.name : n.slice(9)}`;
  }
  if ((state.cand?.application_groups || []).some((g) => g.name === n)) return `Group: ${n}`;
  const a = (state.appCatalog || []).find((x) => x.name.toLowerCase() === n);
  return a ? a.name : n;
};

function appPicker(label, values, opts = { groups: true }) {
  let selected = (values || []).filter((v) => v !== "any").map((v) => v.toLowerCase());
  const chipsBox = h("div", { class: "app-chips", "aria-live": "polite" });
  const search = h("input", { placeholder: "Search applications, e.g. youtube, video, vpn", "aria-label": "Search applications" });
  const cat = h("select", { "aria-label": "Category" }, h("option", { value: "" }, "All categories"));
  const kind = h("select", { "aria-label": "Show" },
    ["all", "applications", "categories", ...(opts.groups ? ["groups"] : [])].map((k) => h("option", { value: k }, k === "all" ? "Everything" : k[0].toUpperCase() + k.slice(1))));
  const results = h("div", { class: "app-results", role: "listbox", "aria-label": "Applications" });
  const drawChips = () => {
    chipsBox.replaceChildren(...(selected.length ? selected.map((n) => h("span", { class: "chip app-chip" }, appLabel(n),
      h("button", { type: "button", class: "chip-x", "aria-label": `Remove ${appLabel(n)}`, onclick: () => { selected = selected.filter((x) => x !== n); drawChips(); drawResults(); } }, "×")))
      : [h("span", { class: "chip any" }, opts.none || "any application")]));
  };
  const drawResults = () => {
    const all = state.appCatalog || [];
    const q = search.value.trim().toLowerCase(), c = cat.value;
    const k = kind.value;
    const pool = [
      ...(k === "all" || k === "groups") && opts.groups ? (state.cand.application_groups || []).map((g) => ({ value: g.name, name: g.name, category: `group · ${g.members.length} members`, kind: "group" })) : [],
      ...(k === "all" || k === "categories") ? (state.appCategories || []).map((x) => ({ value: x.ref, name: `Category: ${x.name}`, category: `${x.apps} apps`, kind: "category", cat: x.name })) : [],
      ...(k === "all" || k === "applications") ? [{ value: "unknown", name: "unknown", category: "(not identified by App Identification)", kind: "app" },
        ...all.map((a) => ({ value: a.name.toLowerCase(), name: a.name, category: a.category, kind: "app", cat: a.category }))] : [],
    ];
    const hits = pool.filter((a) => (!c || a.cat === c) && (!q || a.name.toLowerCase().includes(q) || a.category.toLowerCase().includes(q)));
    const shown = hits.slice(0, 60);
    results.replaceChildren(...shown.map((a) => {
      const n = a.value, on = selected.includes(n);
      return h("button", { type: "button", class: "app-opt" + (on ? " on" : ""), role: "option", "aria-selected": String(on),
        onclick: () => { selected = on ? selected.filter((x) => x !== n) : [...selected, n]; drawChips(); drawResults(); } },
        h("span", { class: a.kind === "app" ? "" : "app-kind-" + a.kind }, a.name), h("span", { class: "muted small" }, a.category));
    }), ...(hits.length > shown.length ? [h("p", { class: "muted small" }, `${hits.length - shown.length} more: narrow the search`)] : []),
    ...(!hits.length ? [h("p", { class: "muted small" }, all.length ? "No application matches." : "The application catalog isn't available.")] : []));
  };
  search.addEventListener("input", drawResults);
  cat.addEventListener("change", drawResults);
  kind.addEventListener("change", drawResults);
  appCatalog().then((all) => {
    [...new Set(all.map((a) => a.category))].filter(Boolean).sort().forEach((c) => cat.append(h("option", { value: c }, c)));
    drawChips();
    drawResults();
  });
  drawChips();
  return {
    node: h("div", { class: "app-picker" },
      h("label", {}, label, h("span", { class: "hint" }, opts.groups
        ? "Applications, categories (every app in one) and application groups. None chosen = any application; the rule acts once App Identification names the connection."
        : "Applications and categories (every app in one).")),
      chipsBox, h("div", { class: "row" }, search, kind, cat), results),
    get: () => selected.slice(),
  };
}

// ---- specs -----------------------------------------------------------------
const ruleSpec = () => ({
  key: "rules", title: "Security rules", singular: "rule", orderable: true,
  note: "Checked top to bottom; the first match wins. Anything unmatched is denied.",
  blank: () => ({ name: "", from: [], to: [], source: [], destination: [], application: [], service: [], action: "allow", log: false, ips_profile: "" }),
  columns: [
    ["Name", (r) => h("strong", {}, r.name)],
    ["From", (r) => chips(r.from)], ["To", (r) => chips(r.to)],
    ["Source", (r) => chips(r.source)], ["Destination", (r) => chips(r.destination)],
    ["Application", (r) => chips((r.application || []).map(appLabel))], ["Service", (r) => chips(r.service)],
    ["Action", (r) => h("span", { class: "action-" + r.action }, r.action)],
    ["Log", (r) => (r.log ? "yes" : "")],
    ["IPS", (r) => (r.ips_profile && r.action === "allow" ? h("span", { class: "chip" }, r.ips_profile) : "")],
  ],
  form: (r) => {
    const f = {
      name: textField("Name", r.name, { required: true }),
      action: selectField("Action", r.action, ["allow", "deny", "reset"], { hint: "reset sends a TCP reset or ICMP unreachable" }),
      from: multiField("From zones", r.from, zoneNames()),
      to: multiField("To zones", r.to, zoneNames()),
      source: multiField("Source", r.source, addrNames(), { hint: "Addresses and groups" }),
      destination: multiField("Destination", r.destination, addrNames(), { hint: "Addresses and groups" }),
      service: multiField("Service", r.service, serviceNames()),
      application: appPicker("Applications", r.application),
      log: checkField("Log matches to the kernel log", r.log),
      ips: selectField("IPS profile", r.ips_profile || "", [{ value: "", label: "(none: not inspected)" }, ...ipsProfileNames()],
        { hint: "Allow rules: inspect the traffic, block or alert by signature severity (Objects → IPS profiles)" }),
    };
    return form(Object.values(f), () => ({
      name: f.name.get(), from: f.from.get(), to: f.to.get(), source: f.source.get(), destination: f.destination.get(),
      application: f.application.get(), service: f.service.get(), action: f.action.get(), log: f.log.get(),
      ips_profile: f.action.get() === "allow" ? f.ips.get() : "",
    }));
  },
});

// NAT: one ordered list, shown as three sections by type. live is GET nat
// (counters, whether public addresses are on their interfaces).
const hostNames = () => state.cand.addresses.filter((a) => /^[0-9.]+(\/32)?$/.test(a.cidr)).map((a) => a.name);
const natIfaces = () => state.cand.interfaces.filter((i) => i.name !== state.cand.system.mgmt_interface).map((i) => i.name);
const addrOf = (n) => (state.cand.addresses.find((a) => a.name === n) || {}).cidr || "";
const natLive = (live, r) => (live || []).find((e) => e.name === r.name) || {};
const hitCount = (n) => (n === null || n === undefined ? "–" : String(n));
const publicCell = (live, r) => {
  if (!r.public_address) return h("span", { class: "muted" }, `${r.interface} address`);
  const l = natLive(live, r);
  return h("span", {}, h("strong", {}, r.public_address), " ", h("span", { class: "mono muted" }, addrOf(r.public_address)),
    l.address_applied === false ? h("span", { class: "badge-threat", title: l.address_error || "" }, "not on the interface yet") : null);
};
const serverCell = (r) => h("span", {}, h("strong", {}, r.server), " ", h("span", { class: "mono muted" }, addrOf(r.server)));

const portForwardSpec = (live) => ({
  key: "nat", title: "Port forwarding", singular: "port forward", orderable: true,
  filter: (r) => r.type === "port-forward",
  note: "A public port to an inside server. Translation only: add a security rule that allows the server's inside address.",
  blank: () => ({ name: "", type: "port-forward", interface: "outside", public_address: "", protocol: "tcp", public_port: "", server: "", server_port: "" }),
  columns: [
    ["Name", (r) => h("strong", {}, r.name)], ["Interface", (r) => r.interface], ["Public", (r) => publicCell(live, r)],
    ["Port", (r) => h("span", { class: "mono" }, `${r.protocol}/${r.public_port}`)], ["Server", serverCell],
    ["Server port", (r) => h("span", { class: "mono" }, r.server_port || r.public_port)],
    ["Connections", (r) => hitCount(natLive(live, r).hits)],
  ],
  form: (r) => {
    const f = {
      name: textField("Name", r.name, { required: true }),
      iface: selectField("Interface", r.interface, natIfaces(), { hint: "Where the traffic arrives, usually outside" }),
      pub: selectField("Public address", r.public_address || "", [{ value: "", label: "(the interface's own address)" }, ...hostNames()],
        { hint: "Or an address object (one host): SJB-OS answers for it on the interface" }),
      proto: selectField("Protocol", r.protocol || "tcp", ["tcp", "udp"]),
      port: textField("Public port", r.public_port, { required: true, placeholder: "443 or 8000-8010" }),
      server: selectField("Server", r.server, hostNames(), { hint: "Address object of the inside server (one host)" }),
      sport: textField("Server port", r.server_port, { placeholder: "same as the public port", hint: "A range keeps its ports" }),
    };
    return form(Object.values(f), () => ({
      name: f.name.get(), type: "port-forward", interface: f.iface.get(), public_address: f.pub.get(), protocol: f.proto.get(),
      public_port: f.port.get(), server: f.server.get(), server_port: f.sport.get(),
    }));
  },
});

const staticNatSpec = (live) => ({
  key: "nat", title: "Static NAT", singular: "static NAT", orderable: true,
  filter: (r) => r.type === "static",
  note: "1:1: every port of a public address goes to one inside server. Translation only: add a security rule that allows the server.",
  blank: () => ({ name: "", type: "static", interface: "outside", public_address: "", server: "", bidirectional: "" }),
  columns: [
    ["Name", (r) => h("strong", {}, r.name)], ["Interface", (r) => r.interface], ["Public", (r) => publicCell(live, r)],
    ["Server", serverCell], ["Bidirectional", (r) => (r.bidirectional === "off" ? "off" : "on")],
    ["In", (r) => hitCount(natLive(live, r).hits)],
    ["Out", (r) => (r.bidirectional === "off" ? "–" : hitCount(natLive(live, r).out_hits))],
  ],
  form: (r) => {
    const f = {
      name: textField("Name", r.name, { required: true }),
      iface: selectField("Interface", r.interface, natIfaces(), { hint: "Where the traffic arrives, usually outside" }),
      pub: selectField("Public address", r.public_address, hostNames(), { hint: "Address object (one host); SJB-OS answers for it on the interface" }),
      server: selectField("Server", r.server, hostNames(), { hint: "Address object of the inside server (one host)" }),
      bidi: checkField("Bidirectional: the server's own outbound traffic leaves from the public address", r.bidirectional !== "off"),
    };
    return form(Object.values(f), () => ({
      name: f.name.get(), type: "static", interface: f.iface.get(), public_address: f.pub.get(), server: f.server.get(),
      bidirectional: f.bidi.get() ? "" : "off",
    }));
  },
});

const natSpec = (live) => ({
  key: "nat", title: "Source NAT", singular: "source NAT rule", orderable: true,
  filter: (r) => r.type === "masquerade",
  note: "Traffic leaving through the egress zone takes that interface's address.",
  blank: () => ({ name: "", from: [], to: [], source: [], type: "masquerade" }),
  columns: [
    ["Name", (r) => h("strong", {}, r.name)], ["From", (r) => chips(r.from)], ["To", (r) => chips(r.to)],
    ["Source", (r) => chips(r.source)], ["Type", (r) => r.type], ["Connections", (r) => hitCount(natLive(live, r).hits)],
  ],
  form: (r) => {
    const f = {
      name: textField("Name", r.name, { required: true }),
      from: multiField("From zones", r.from, zoneNames()),
      to: multiField("To zones", r.to, zoneNames()),
      source: multiField("Source", r.source, addrNames()),
    };
    return form(Object.values(f), () => ({ name: f.name.get(), from: f.from.get(), to: f.to.get(), source: f.source.get(), type: "masquerade" }));
  },
});

const addressSpec = () => ({
  key: "addresses", title: "Addresses", singular: "address",
  blank: () => ({ name: "", cidr: "" }),
  columns: [["Name", (a) => h("strong", {}, a.name)], ["Address or prefix", (a) => h("span", { class: "mono" }, a.cidr)]],
  form: (a) => {
    const f = { name: textField("Name", a.name, { required: true }), cidr: textField("Address or prefix", a.cidr, { required: true, placeholder: "10.0.0.0/8 or 10.0.0.1" }) };
    return form(Object.values(f), () => ({ name: f.name.get(), cidr: f.cidr.get() }));
  },
});

const groupSpec = () => ({
  key: "address_groups", title: "Address groups", singular: "address group",
  note: "Static groups list addresses; dynamic groups hold whatever IPs are registered with a tag.",
  blank: () => ({ name: "", static: [], tag: "" }),
  columns: [
    ["Name", (g) => h("strong", {}, g.name)],
    ["Members", (g) => (g.tag ? [h("span", { class: "chip" }, "tag: " + g.tag), " ", h("span", { class: "muted small" }, `${state.status.tags[g.tag] || 0} registered`)] : chips(g.static, "none"))],
  ],
  form: (g) => {
    const kind = selectField("Kind", g.tag ? "tag" : "static", [{ value: "static", label: "Static: a list of addresses" }, { value: "tag", label: "Dynamic: IPs registered with a tag" }]);
    const name = textField("Name", g.name, { required: true });
    const members = multiField("Members", g.static, state.cand.addresses.map((a) => a.name), { noAny: true });
    const tag = textField("Tag", g.tag, { placeholder: "e.g. quarantine", hint: "Registered through the tag API or the Tags page" });
    const sel = kind.node.querySelector("select");
    const sync = () => { members.node.classList.toggle("hidden", sel.value !== "static"); tag.node.classList.toggle("hidden", sel.value !== "tag"); };
    sel.addEventListener("change", sync);
    sync();
    return form([name, kind, members, tag], () => (sel.value === "tag" ? { name: name.get(), tag: tag.get(), static: [] } : { name: name.get(), static: members.get(), tag: "" }));
  },
});

const serviceSpec = () => ({
  key: "services", title: "Services", singular: "service",
  blank: () => ({ name: "", protocol: "tcp", ports: "" }),
  columns: [["Name", (s) => h("strong", {}, s.name)], ["Protocol", (s) => s.protocol], ["Ports", (s) => h("span", { class: "mono" }, s.ports || "")]],
  form: (s) => {
    const f = {
      name: textField("Name", s.name, { required: true }),
      protocol: selectField("Protocol", s.protocol, ["tcp", "udp", "icmp"]),
      ports: textField("Ports", s.ports, { placeholder: "80,443,8000-8080", hint: "Leave empty for icmp" }),
    };
    return form(Object.values(f), () => ({ name: f.name.get(), protocol: f.protocol.get(), ports: f.ports.get() }));
  },
});

const zoneSpec = () => ({
  key: "zones", title: "Zones", singular: "zone",
  blank: () => ({ name: "" }),
  columns: [["Name", (z) => h("strong", {}, z.name)], ["Interfaces", (z) => chips(state.cand.interfaces.filter((i) => i.zone === z.name).map((i) => i.name), "none")]],
  form: (z) => {
    const name = textField("Name", z.name, { required: true });
    return form([name], () => ({ name: name.get() }));
  },
});

const vrfNames = () => state.cand.vrfs.map((v) => v.name);
const isVLAN = (name) => /\.\d+$/.test(name);

const vrfSpec = (devs) => ({
  key: "vrfs", title: "VRFs", singular: "VRF",
  note: "Separate routing tables. default and mgmt are built in. VLAN subinterfaces join a VRF; routes name one.",
  blank: () => ({ name: "", table: 0 }),
  columns: [
    ["Name", (v) => h("strong", {}, v.name)],
    ["Table", (v) => (v.table ? String(v.table) : h("span", { class: "muted" }, "auto"))],
    ["Interfaces", (v) => chips(state.cand.interfaces.filter((i) => i.vrf === v.name).map((i) => i.name), "none")],
    ["State", (v) => devState(devs, "vrf-" + v.name)],
  ],
  form: (v) => {
    const name = textField("Name", v.name, { required: true, placeholder: "lab-a", hint: "Up to 11 characters" });
    const table = textField("Table", v.table ? String(v.table) : "", { placeholder: "auto", hint: "1001-65535, or leave empty" });
    return form([name, table], () => ({ name: name.get(), table: Number(table.get() || 0) }));
  },
});

function devState(devs, name) {
  const s = (devs || []).find((d) => d.name === name);
  if (!s) return h("span", { class: "muted" }, "not committed");
  return s.ok ? h("span", { class: "action-allow" }, "up")
    : [h("span", { class: "action-deny" }, "not up"), s.error ? h("div", { class: "muted small" }, s.error) : null];
}

// nicState: a NIC's address comes from the deployment (mgmt always; inside
// and outside unless the config sets one), or from the config.
function nicState(nics, i) {
  const s = (nics || []).find((n) => n.name === i.name);
  if (!s) return h("span", { class: "muted" }, "deployment settings");
  if (s.address === "trunk-only") return s.applied ? h("span", { class: "action-allow" }, "trunk: no address, untagged dropped")
    : [h("span", { class: "action-deny" }, "trunk not applied yet"), s.error ? h("div", { class: "muted small" }, s.error) : null];
  return s.applied ? h("span", { class: "action-allow" }, "address applied")
    : [h("span", { class: "action-deny" }, "address not applied"), s.error ? h("div", { class: "muted small" }, s.error) : null];
}

const ifaceSpec = (devs, nics) => ({
  key: "interfaces", title: "Interfaces", singular: "interface",
  note: "The NICs are mgmt, inside and outside; mgmt has no zone and is never filtered. Add a VLAN as parent.id, e.g. inside.20 (the port group must trunk VLANs: VLAN 4095). A NIC with no zone that carries VLANs is a trunk: no address, untagged traffic dropped.",
  blank: () => ({ name: "", zone: "", address: "", vrf: "" }),
  columns: [
    ["Name", (i) => h("strong", {}, i.name)],
    ["Zone", (i) => i.zone || h("span", { class: "muted" }, i.name === state.cand.system.mgmt_interface ? "none" : "trunk (VLANs only)")],
    ["VRF", (i) => (i.name === state.cand.system.mgmt_interface ? "mgmt" : i.vrf || h("span", { class: "muted" }, "default"))],
    ["Address", (i) => h("span", { class: "mono" }, i.address || "")],
    ["State", (i) => (isVLAN(i.name) ? devState(devs, i.name) : nicState(nics, i))],
  ],
  form: (i) => {
    const f = {
      name: textField("Name", i.name, { required: true, placeholder: "inside or inside.20" }),
      zone: selectField("Zone", i.zone || "", [{ value: "", label: "(none: mgmt, or a trunk carrying VLANs)" }, ...zoneNames()],
        { hint: "No zone on inside or outside makes it a trunk: VLAN subinterfaces only, no address, untagged traffic dropped" }),
      vrf: selectField("VRF", i.vrf || "", [{ value: "", label: "default" }, ...vrfNames()], { hint: "VLAN subinterfaces only" }),
      address: textField("Address", i.address, { placeholder: "10.20.0.1/24", hint: "Applied at commit, replacing the deployment's address or DHCP on inside/outside; leave empty to keep the deployment's. Informational on mgmt." }),
    };
    return form(Object.values(f), () => ({ name: f.name.get(), zone: f.zone.get(), address: f.address.get(), vrf: f.vrf.get() }));
  },
});

// ---- pages -----------------------------------------------------------------
const sayings = [
  "standing guard at the border.",
  "every packet shows its papers.",
  "junk stopped, good traffic waved through.",
  "the quarantine queue is orderly.",
];

function card(label, value, sub) {
  return h("div", { class: "card" }, h("div", { class: "label" }, label), h("div", { class: "value" }, value), sub ? h("div", { class: "muted small" }, sub) : null);
}

// ---- dashboard charts ----------------------------------------------------------
// Hand-made SVG (the CSP allows no inline styles: sizes and positions go
// through the CSSOM). Colours are CSS variables (app.css): interfaces take
// the categorical slots in a fixed order by name, threats an ordinal red
// ramp by severity.
const SVGNS = "http://www.w3.org/2000/svg";
function sv(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null) el.setAttribute(k, v);
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return el;
}
const prefGet = (k, d) => { try { return localStorage.getItem(k) || d; } catch { return d; } };
const prefSet = (k, v) => { try { localStorage.setItem(k, v); } catch { /* not remembered */ } };
state.dash = { window: prefGet("sjb.dash.window", "1h"), report: null };

const fmtBps = (b) => {
  const u = ["b/s", "Kb/s", "Mb/s", "Gb/s"];
  let i = 0;
  while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
  return `${b >= 100 || i === 0 ? Math.round(b) : b.toFixed(1)} ${u[i]}`;
};
const niceMax = (v) => {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  // Steps that split into four even ticks.
  return [1, 2, 4, 6, 8, 10].map((m) => m * p).find((m) => m >= v);
};
const tickTime = (t, win) => {
  const d = new Date(t * 1000);
  return win === "7d" ? d.toLocaleDateString(undefined, { weekday: "short", day: "numeric" })
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
};
const pointTime = (t, step) => {
  const a = new Date(t * 1000), b = new Date((t + step) * 1000);
  const o = { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" };
  return `${a.toLocaleString(undefined, o)} – ${b.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}`;
};
// Interfaces keep their colour whatever the window shows: inside, outside,
// then the other zoned interfaces by name.
const ifaceSlot = (name) => {
  const names = (state.cand?.interfaces || []).filter((i) => i.zone).map((i) => i.name)
    .sort((a, b) => (a === "inside" ? -1 : b === "inside" ? 1 : a === "outside" ? -1 : b === "outside" ? 1 : a.localeCompare(b)));
  const i = names.indexOf(name);
  return (i < 0 ? names.length : i) % 8 + 1;
};

// Plot frame shared by the time charts: viewBox units, y grid with labels,
// x time ticks, and a hover layer that reports the point under the pointer.
function timeFrame(times, step, win, yMax, yFmt, tipFor) {
  const W = 640, H = 250, L = 58, R = 10, T = 10, B = 24, pw = W - L - R, ph = H - T - B;
  const n = times.length;
  const x = (i) => L + (i + 0.5) * (pw / n);
  const y = (v) => T + ph - (v / yMax) * ph;
  const svg = sv("svg", { viewBox: `0 0 ${W} ${H}`, class: "viz", role: "img" });
  const grid = sv("g", { class: "viz-grid" });
  for (let k = 0; k <= 4; k++) {
    const v = (yMax * k) / 4, yy = y(v);
    grid.append(sv("line", { x1: L, x2: W - R, y1: yy, y2: yy, class: k ? "grid" : "base" }),
      sv("text", { x: L - 6, y: yy + 4, "text-anchor": "end", class: "tick" }, yFmt(v)));
  }
  const every = Math.ceil(n / 5);
  for (let i = 0; i < n; i += every) grid.append(sv("text", { x: x(i), y: H - 6, "text-anchor": "middle", class: "tick" }, tickTime(times[i], win)));
  svg.append(grid);
  const guide = sv("line", { y1: T, y2: T + ph, class: "guide hidden-viz" });
  const plot = sv("g", {});
  svg.append(plot, guide);
  const wrap = h("div", { class: "chart" }, svg);
  const tip = h("div", { class: "chart-tip hidden" });
  wrap.append(tip);
  const hit = sv("rect", { x: L, y: T, width: pw, height: ph, class: "hit" });
  const move = (e) => {
    const r = svg.getBoundingClientRect();
    const vx = ((e.clientX - r.left) / r.width) * W;
    const i = Math.max(0, Math.min(n - 1, Math.floor((vx - L) / (pw / n))));
    guide.setAttribute("x1", x(i)); guide.setAttribute("x2", x(i));
    guide.classList.remove("hidden-viz");
    tip.replaceChildren(h("div", { class: "tip-time" }, pointTime(times[i], step)), ...tipFor(i));
    tip.classList.remove("hidden");
    const left = ((x(i) / W) * r.width);
    tip.style.left = `${Math.min(Math.max(left + 12, 0), r.width - tip.offsetWidth - 4)}px`;
    if (left + 12 + tip.offsetWidth > r.width) tip.style.left = `${Math.max(0, left - tip.offsetWidth - 12)}px`;
    tip.style.top = "8px";
  };
  hit.addEventListener("pointermove", move);
  hit.addEventListener("pointerleave", () => { tip.classList.add("hidden"); guide.classList.add("hidden-viz"); });
  svg.append(hit);
  return { wrap, plot, x, y, pw, n, T, ph };
}

function legend(items) {
  return h("div", { class: "legend" }, items.map((it) => h("span", { class: `legend-item ${it.cls}` }, h("span", { class: "swatch" }), it.name)));
}

// Each interface's received traffic (outside: downloads, inside: uploads);
// in and out added together would draw inside and outside on top of each
// other, since forwarded traffic crosses both. Points with no samples are
// gaps, not zeros.
function throughputChart(r) {
  const series = r.interfaces.slice(0, 8);
  const total = series.map((s) => s.in);
  const yMax = niceMax(Math.max(1, ...total.flat()));
  const f = timeFrame(r.times, r.step, r.window, yMax, fmtBps, (i) => series.map((s) =>
    r.covered[i] ? h("div", { class: `tip-row ser-${ifaceSlot(s.name)}` }, h("span", { class: "swatch" }), h("strong", {}, s.name), ` in ${fmtBps(s.in[i])} · out ${fmtBps(s.out[i])}`)
      : h("div", { class: "muted" }, s.name + ": no samples")));
  series.forEach((s, k) => {
    let d = "", pen = false;
    total[k].forEach((v, i) => {
      if (!r.covered[i]) { pen = false; return; }
      d += `${pen ? "L" : "M"}${f.x(i).toFixed(1)},${f.y(v).toFixed(1)}`;
      pen = true;
    });
    f.plot.append(sv("path", { d, class: `line ser-${ifaceSlot(s.name)}` }));
  });
  return [f.wrap, series.length > 1 ? legend(series.map((s) => ({ name: s.name, cls: `ser-${ifaceSlot(s.name)}` }))) : null];
}

function threatChart(r) {
  const sev = ["critical", "major", "minor", "informational"];
  const sums = r.times.map((_, i) => sev.reduce((a, k) => a + (r.threats.series[k]?.[i] || 0), 0));
  // Whole-number ticks for counts.
  const yMax = Math.max(4, Math.ceil(Math.max(...sums) / 4) * 4);
  const f = timeFrame(r.times, r.step, r.window, yMax, (v) => String(Math.round(v)), (i) =>
    sev.filter((k) => r.threats.series[k]?.[i]).map((k) => h("div", { class: `tip-row sev-${k}` }, h("span", { class: "swatch" }), `${k}: ${r.threats.series[k][i]}`)).concat(sums[i] ? [] : [h("div", { class: "muted" }, "none")]));
  const bw = Math.max(1, f.pw / f.n - 2);
  r.times.forEach((_, i) => {
    let acc = 0;
    // Most severe at the bottom, by the baseline.
    for (const k of sev) {
      const v = r.threats.series[k]?.[i] || 0;
      if (!v) continue;
      const y0 = f.y(acc), y1 = f.y(acc + v);
      f.plot.append(sv("rect", { x: (f.x(i) - bw / 2).toFixed(1), y: y1.toFixed(1), width: bw.toFixed(1), height: Math.max(1, y0 - y1).toFixed(1), rx: 2, class: `seg sev-${k}` }));
      acc += v;
    }
  });
  return [f.wrap, legend(sev.map((k) => ({ name: k, cls: `sev-${k}` })))];
}

function barList(items, empty, wide) {
  if (!items.length) return h("p", { class: "muted small" }, empty);
  const max = Math.max(...items.map((i) => i.value), 1);
  return h("div", { class: "barlist" + (wide ? " wide" : "") }, items.map((it) => {
    const fill = h("span", { class: "bar-fill" });
    fill.style.width = `${Math.max(1, (it.value / max) * 100)}%`;
    return h("div", { class: "bar-row" },
      h("button", { class: "link bar-label", title: it.title || it.label, onclick: it.onclick }, it.label),
      h("span", { class: "bar-track" }, fill),
      h("span", { class: "bar-value" }, it.text, it.badge ? h("span", { class: "badge-threat", title: "IPS matches from this host" }, it.badge) : null));
  }));
}

function panel(title, sub, ...body) {
  return h("section", { class: "panel dash-panel" }, h("div", { class: "dash-head" }, h("h3", {}, title), sub ? h("span", { class: "muted small" }, sub) : null), ...body);
}

function chartsFor(r) {
  const collecting = r.samples === 0;
  const wait = h("p", { class: "muted small" }, "Collecting: a sample is taken every minute, so the charts fill in over the next few minutes.");
  const th = r.threats;
  const goLog = (kind, q) => { state.logs.kind = kind; state.logs.q = q; if (location.hash === "#logs") route(); else location.hash = "#logs"; };
  return [
    panel("Throughput", collecting ? "" : "received per interface",
      collecting || !r.interfaces.length ? (collecting ? wait : h("p", { class: "muted small" }, "No traffic on the data interfaces in this period.")) : throughputChart(r)),
    panel("Top applications", "by bytes",
      !r.app_id ? h("p", { class: "muted small" }, "Applications need App Identification (set system app-identification on).")
        : barList(r.apps.map((a) => ({ label: a.name, value: a.bytes, text: `${fmtBytes(a.bytes)} · ${a.connections} conn`, onclick: () => { location.hash = "#apps"; } })),
          collecting ? "Collecting…" : "No connections finished in this period yet.")),
    panel("Threats", th.blocked + th.alerted ? `${th.blocked} blocked · ${th.alerted} alerted` : "",
      !r.ips && !(th.blocked + th.alerted) ? h("p", { class: "muted small" }, "No rules use an IPS profile (Security → Policy → IPS profile).")
        : th.blocked + th.alerted === 0 ? h("p", { class: "muted small" }, collecting ? "Collecting…" : "No threats in this period. Quiet at the border.")
        : [threatChart(r), h("h4", { class: "dash-sub" }, "Top signatures"),
          barList(th.top.map((t) => ({ label: `${t.sid} ${t.signature}`, title: `${t.signature} (${t.severity})`, value: t.count, text: `${t.count} · ${t.severity}`, onclick: () => goLog("threat", `sid = ${t.sid}`) })), "", true)]),
    panel("Top hosts", "by bytes",
      !r.app_id ? h("p", { class: "muted small" }, "Hosts need App Identification (set system app-identification on).")
        : barList(r.hosts.map((x) => ({ label: x.name, value: x.bytes, text: `${fmtBytes(x.bytes)} · ${x.connections} conn`, badge: x.threats ? `${x.threats} threat${x.threats > 1 ? "s" : ""}` : null, onclick: () => goLog("traffic", `src = ${x.name}`) })),
          collecting ? "Collecting…" : "No connections finished in this period yet.")),
  ];
}

function dashboardCharts() {
  const D = state.dash;
  const grid = h("div", { class: "dash-grid" });
  const draw = (r) => grid.replaceChildren(...chartsFor(r));
  const load = async () => {
    try {
      const r = await api("GET", `stats?window=${D.window}`);
      D.report = r;
      draw(r);
    } catch (e) {
      if (e.status !== 401) grid.replaceChildren(h("div", { class: "panel" }, errorBox(e)));
    }
  };
  const pick = (w) => h("button", { class: D.window === w ? "active" : "", onclick: () => { D.window = w; prefSet("sjb.dash.window", w); D.report = null; route(); } }, w);
  const sec = h("section", { class: "dash" },
    h("div", { class: "page-head" }, h("h2", {}, "Activity"), h("span", { class: "seg", role: "group", "aria-label": "Period" }, pick("1h"), pick("24h"), pick("7d"))),
    grid);
  if (D.report && D.report.window === D.window) draw(D.report);
  else grid.append(h("p", { class: "muted" }, "Loading…"));
  load();
  clearInterval(state.dashTimer);
  state.dashTimer = setInterval(() => (document.body.contains(sec) ? load() : clearInterval(state.dashTimer)), 30000);
  return sec;
}

function pageDashboard() {
  const st = state.status;
  const c = st.counts || {};
  const quarantined = st.tags.quarantine || 0;
  const totalTags = Object.values(st.tags).reduce((a, b) => a + b, 0);
  const say = sayings[(st.running_revision + totalTags) % sayings.length];
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Dashboard")),
    h("p", { class: "tagline" }, `Revision ${st.running_revision} is on duty, ${say}`),
    h("div", { class: "cards" },
      card("Running revision", st.running_revision, st.uncommitted_changes ? "candidate has changes" : "candidate matches"),
      card("Security rules", c.rules ?? 0, `${c.nat ?? 0} NAT rules`),
      card("Zones", c.zones ?? 0),
      card("Objects", (c.addresses ?? 0) + (c.address_groups ?? 0) + (c.services ?? 0), `${c.addresses ?? 0} addresses, ${c.address_groups ?? 0} groups, ${c.services ?? 0} services`),
      card("Quarantined hosts", quarantined, `${totalTags} tag registrations in all`),
      card("SJB-OS", st.version || "dev", st.hostname || ""),
    ),
    can("monitoring") ? dashboardCharts() : null,
    h("section", { class: "panel" }, h("h2", {}, "Interfaces"),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Interface"), h("th", {}, "Zone"), h("th", {}, "Addresses"))),
        h("tbody", {}, (st.interfaces || []).map((i) => h("tr", {}, h("td", {}, h("strong", {}, i.name)), h("td", {}, i.zone || "none"), h("td", { class: "mono" }, (i.addrs || []).join(", ") || h("span", { class: "muted" }, "no address")))))))),
  );
}

async function pagePolicy() {
  await appCatalog(); // so the table shows application names as the catalog spells them
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Policy"), h("span", { class: "spacer" }),
      h("button", { onclick: previewRuleset }, "Preview ruleset")),
    listSection(ruleSpec()),
    listSection(decryptRuleSpec()));
}

async function previewRuleset() {
  try {
    const p = await api("GET", "preview");
    modal("nftables ruleset the candidate compiles to", h("div", {},
      p.warnings.length ? h("ul", {}, p.warnings.map((w) => h("li", {}, w))) : null,
      h("pre", { class: "block" }, p.ruleset)), { submit: null, wide: true });
  } catch (e) { toast(e.message); }
}

async function pageNat() {
  const live = can("monitoring", "view") ? await api("GET", "nat").catch(() => []) : [];
  return h("div", {}, h("div", { class: "page-head" }, h("h1", {}, "NAT"), h("span", { class: "spacer" }), h("button", { onclick: route }, "Refresh")),
    listSection(portForwardSpec(live)), listSection(staticNatSpec(live)), listSection(natSpec(live)));
}
const pageObjects = async () => {
  await appCatalog();
  return h("div", {}, h("div", { class: "page-head" }, h("h1", {}, "Objects")),
    listSection(addressSpec()), listSection(groupSpec()), listSection(serviceSpec()), listSection(appGroupSpec()), listSection(ipsProfileSpec()),
    listSection(decryptProfileSpec()), listSection(decryptExclusionSpec()));
};

const IPS_SEVERITIES = ["critical", "major", "minor", "informational"];
const IPS_DEFAULTS = { critical: "block", major: "block", minor: "alert", informational: "ignore" };
const ipsProfileNames = () => {
  const own = (state.cand.ips_profiles || []).map((p) => p.name);
  return own.includes("default") ? own : ["default", ...own];
};

const ipsProfileSpec = () => ({
  key: "ips_profiles", title: "IPS profiles", singular: "IPS profile",
  note: "What to do when a signature matches a rule's traffic, by severity: block (drop it and the rest of the connection), alert (let it through and log it) or ignore. The built-in default blocks critical and major, alerts on minor and ignores informational; a profile named default replaces it.",
  blank: () => ({ name: "", critical: "", major: "", minor: "", informational: "" }),
  columns: [
    ["Name", (p) => h("strong", {}, p.name)],
    ...IPS_SEVERITIES.map((sev) => [sev[0].toUpperCase() + sev.slice(1), (p) => {
      const a = p[sev] || IPS_DEFAULTS[sev];
      return h("span", { class: a === "block" ? "action-deny" : a === "alert" ? "action-reset" : "muted", title: p[sev] ? "" : "from the default profile" }, a);
    }]),
  ],
  form: (p) => {
    const name = textField("Name", p.name, { required: true, placeholder: "strict" });
    const sel = Object.fromEntries(IPS_SEVERITIES.map((sev) => [sev, selectField(sev[0].toUpperCase() + sev.slice(1), p[sev] || "",
      [{ value: "", label: `(default: ${IPS_DEFAULTS[sev]})` }, "block", "alert", "ignore"])]));
    return form([name, ...Object.values(sel)], () => ({ name: name.get(), ...Object.fromEntries(IPS_SEVERITIES.map((sev) => [sev, sel[sev].get()])) }));
  },
});

// ---- TLS decryption ---------------------------------------------------------
const DECRYPT_DEFAULTS = { bad_certificate: "warn", unsupported: "pass", pinned: "exclude" };
const decryptProfileNames = () => {
  const own = (state.cand.decryption_profiles || []).map((p) => p.name);
  return own.includes("default") ? own : ["default", ...own];
};

const decryptRuleSpec = () => ({
  key: "decryption_rules", title: "Decryption rules", singular: "decryption rule", orderable: true,
  note: "Which TLS connections the firewall decrypts, so the rules above, App Identification and the IPS see inside them. First match wins; anything unmatched isn't decrypted. Built-in and listed exclusions are never decrypted.",
  blank: () => ({ name: "", from: [], to: [], source: [], destination: [], service: [], action: "decrypt", profile: "" }),
  columns: [
    ["Name", (r) => h("strong", {}, r.name)],
    ["From", (r) => chips(r.from)], ["To", (r) => chips(r.to)],
    ["Source", (r) => chips(r.source)], ["Destination", (r) => chips(r.destination)],
    ["Service", (r) => chips(r.service, "443")],
    ["Action", (r) => h("span", { class: r.action === "decrypt" ? "action-allow" : "muted" }, r.action)],
    ["Profile", (r) => (r.action === "decrypt" ? h("span", { class: "chip" }, r.profile || "default") : "")],
  ],
  form: (r) => {
    const tcp = state.cand.services.filter((x) => x.protocol === "tcp").map((x) => x.name);
    const f = {
      name: textField("Name", r.name, { required: true }),
      action: selectField("Action", r.action, ["decrypt", "no-decrypt"], { hint: "no-decrypt exempts the traffic from the rules below it" }),
      from: multiField("From zones", r.from, zoneNames()),
      to: multiField("To zones", r.to, zoneNames()),
      source: multiField("Source", r.source, addrNames(), { hint: "Addresses and groups" }),
      destination: multiField("Destination", r.destination, addrNames(), { hint: "Addresses and groups" }),
      service: multiField("Service", r.service, tcp, { hint: "TCP services; any means port 443" }),
      profile: selectField("Profile", r.profile || "", [{ value: "", label: "(default)" }, ...decryptProfileNames()],
        { hint: "What to do with bad certificates, undecryptable and pinned traffic (Objects → Decryption profiles)" }),
    };
    return form(Object.values(f), () => ({
      name: f.name.get(), from: f.from.get(), to: f.to.get(), source: f.source.get(), destination: f.destination.get(),
      service: f.service.get(), action: f.action.get(), profile: f.action.get() === "decrypt" ? f.profile.get() : "",
    }));
  },
});

const decryptProfileSpec = () => ({
  key: "decryption_profiles", title: "Decryption profiles", singular: "decryption profile",
  note: "What decryption does when the usual doesn't apply. The built-in default: a site with a bad certificate is shown to the browser as untrusted (it warns, as without the firewall); traffic that can't be decrypted passes through; a client that rejects the firewall's certificate (a pinned app) is passed through from then on; QUIC is blocked so browsers use TLS.",
  blank: () => ({ name: "", bad_certificate: "", unsupported: "", pinned: "", allow_quic: false }),
  columns: [
    ["Name", (p) => h("strong", {}, p.name)],
    ...[["Bad certificate", "bad_certificate"], ["Can't decrypt", "unsupported"], ["Pinned apps", "pinned"]].map(([t, k]) => [t, (p) => {
      const a = p[k] || DECRYPT_DEFAULTS[k];
      return h("span", { class: a === "block" ? "action-deny" : "", title: p[k] ? "" : "from the default profile" }, a);
    }]),
    ["QUIC", (p) => (p.allow_quic ? "allowed" : h("span", { class: "muted" }, "blocked"))],
  ],
  form: (p) => {
    const name = textField("Name", p.name, { required: true, placeholder: "strict" });
    const bad = selectField("Bad server certificate", p.bad_certificate || "", [{ value: "", label: "(default: warn)" }, "warn", "block"],
      { hint: "warn: the browser shows its own warning; block: refuse" });
    const uns = selectField("Can't be decrypted", p.unsupported || "", [{ value: "", label: "(default: pass)" }, "pass", "block"],
      { hint: "Old TLS, client certificates, not TLS, encrypted client hello" });
    const pin = selectField("Client rejects the certificate", p.pinned || "", [{ value: "", label: "(default: exclude)" }, "exclude", "block"],
      { hint: "exclude: pass that server through from then on (24 h)" });
    const quic = checkField("Let QUIC (UDP 443) through undecrypted", !!p.allow_quic);
    return form([name, bad, uns, pin, quic], () => ({ name: name.get(), bad_certificate: bad.get(), unsupported: uns.get(), pinned: pin.get(), allow_quic: quic.get() }));
  },
});

const decryptExclusionSpec = () => ({
  key: "decryption_exclusions", title: "Decryption exclusions", singular: "decryption exclusion",
  note: "Server names never decrypted, on top of SJB-OS's built-in list (banking, payment, health, government). bank.example covers it and everything under it; *.bank.example only what's under it.",
  blank: () => ({ name: "", domains: [] }),
  columns: [["Name", (e) => h("strong", {}, e.name)], ["Server names", (e) => chips(e.domains, "none")]],
  form: (e) => {
    const name = textField("Name", e.name, { required: true, placeholder: "our-bank" });
    const domains = listField("Server names", e.domains, "comma-separated, e.g. bank.example, *.pay.example");
    return form([name, domains], () => ({ name: name.get(), domains: domains.get().map((d) => d.toLowerCase()) }));
  },
});

async function pageDecryption() {
  const st = await api("GET", "decryption");
  let learned = [];
  try { learned = await api("GET", "decryption/learned"); } catch (e) { /* tlsd not running */ }
  const ca = st.ca || {};
  const when = (t) => (t && !t.startsWith("0001") ? new Date(t).toLocaleDateString() : "");
  const gen = h("button", { class: ca.present ? "" : "primary", onclick: () => confirmDialog(ca.present ? "Replace the decryption CA?" : "Generate a decryption CA?",
    ca.present ? "Clients that trust the current CA must be given the new certificate, or decrypted sites will fail on them." :
      "SJB-OS makes a CA on the firewall. Its private key never leaves it. Install the certificate on the clients you decrypt.",
    async () => { const r = await api("POST", "decryption/ca/generate", {}); toast(`New CA, fingerprint ${r.fingerprint.slice(0, 23)}…`); route(); },
    ca.present ? "Replace" : "Generate", ca.present) }, ca.present ? "Generate a new CA" : "Generate CA");
  const imp = h("button", { onclick: () => {
    const cert = textArea("CA certificate (PEM), then any intermediates above it, in order", "", { placeholder: "-----BEGIN CERTIFICATE-----", rows: 6 });
    const key = textArea("Private key (PEM, unencrypted)", "", { placeholder: "-----BEGIN PRIVATE KEY-----" });
    modal("Import a CA", h("div", {},
      h("p", { class: "muted small" }, "Your own CA (a subordinate CA of your PKI is best). The key stays on the firewall and is never shown again."),
      cert.node, key.node), { submit: "Import", wide: true, onSubmit: async () => {
        const r = await api("POST", "decryption/ca/import", { cert: cert.get(), key: key.get() });
        toast(`CA imported: ${r.subject}`); route();
      } });
  } }, "Import a CA");
  const counts = st.counts || {};
  const decisions = ["decrypted", "would-decrypt", "excluded", "learned", "passed", "blocked", "failed"];
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Decryption"), h("span", { class: "spacer" }), can("decryption-ca", "change") ? [imp, gen] : null),
    h("p", { class: "tagline" }, "Sealed parcels are opened at the border, then sealed again."),
    h("div", { class: "cards" },
      card("State", stateBadge(st.state), st.state_detail || ""),
      card("CA", ca.present ? (ca.source === "imported" ? "imported" : "generated") : h("span", { class: "muted" }, "none"),
        ca.present ? `valid until ${when(ca.not_after)}` : "generate or import one"),
      card("Connections", String(st.active || 0), `being handled now${st.max_active ? ` (limit ${st.max_active})` : ""}`),
      card("Learned", String(st.learned || 0), "pinned servers passed through"),
      card("vCPU", String(st.cpus || "?"), st.cpus < 4 ? "give the VM 4 for decryption" : "4 recommended"),
    ),
    h("section", { class: "panel" }, h("h2", {}, "Decryption CA"),
      ca.present ? h("div", {},
        h("p", {}, ca.subject),
        h("p", { class: "mono small" }, "SHA-256 " + ca.fingerprint),
        h("p", {}, h("a", { href: "/ui/api/decryption/ca.crt", download: "sjb-os-decryption-ca.crt" }, "Download the certificate"),
          h("span", { class: "muted small" }, " to install as a trusted root on the clients you decrypt; check the fingerprint on each.")))
        : h("p", { class: "muted" }, "No CA yet: until there is one, connections pass through undecrypted.")),
    h("section", { class: "panel" }, h("h2", {}, "Rules and exclusions"),
      (st.rules || []).length ? chips(st.rules) : h("p", { class: "muted" }, "No decryption rules. Add one on the Policy page (Decryption rules), or in the CLI: set decryption-rule NAME from inside to outside action decrypt."),
      h("p", { class: "muted small" }, `Built-in exclusions (banking, payment, health, government): ${st.builtin_exclusions ? "on" : "off"}. Add your own on the Objects page.`)),
    h("section", { class: "panel" }, h("h2", {}, "Since tlsd started"),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, decisions.map((d) => h("th", {}, d)))),
        h("tbody", {}, h("tr", {}, decisions.map((d) => h("td", { class: "mono" }, String(counts[d] || 0))))))),
      h("p", { class: "muted small" }, "Each connection is in Logs → Decryption: the server name and what happened, never what was inside.")),
    h("section", { class: "panel" }, h("div", { class: "page-head" }, h("h2", {}, "Learned (pinned) servers"), h("span", { class: "spacer" }),
      learned.length && can("decryption", "change") ? h("button", { onclick: () => confirmDialog("Decrypt these servers again?", "Their clients may fail again, and be learned again.",
        async () => { const r = await api("POST", "decryption/learned/clear", {}); toast(`${r.cleared} forgotten`); route(); }, "Clear") }, "Clear") : null),
      learned.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Server name", "Address", "Passed through until"].map((t) => h("th", {}, t)))),
        h("tbody", {}, learned.map((e) => h("tr", {}, h("td", {}, e.server_name), h("td", { class: "mono" }, e.ip), h("td", {}, new Date(e.expires).toLocaleString()))))))
        : h("p", { class: "muted" }, "None: every client accepted the firewall's certificate.")),
    h("section", { class: "panel" }, h("h2", {}, "Before you decrypt"),
      h("ul", { class: "small" },
        h("li", {}, "Decrypting other people's traffic can be unlawful without their knowledge or consent. Decrypt only devices you own or run, for users who have been told."),
        h("li", {}, "The firewall sees passwords, messages and personal data in the clear while it passes them on. Exclusions reduce this; the built-in list is not complete."),
        h("li", {}, "Anyone with the CA's key can impersonate any site to clients that trust it. It sits on the VM's disk: VM snapshots, backups and clones carry it."),
        h("li", {}, "Pinned apps, client certificates, most Android apps and encrypted client hello can't be decrypted; they pass through."),
        h("li", {}, "SJB-OS is an experimental lab demonstration, not a security product."))));
}

const appGroupSpec = () => ({
  key: "application_groups", title: "Application groups", singular: "application group",
  note: "Name a set of applications and categories, then use it in rules (Policy → Applications).",
  blank: () => ({ name: "", members: [] }),
  columns: [
    ["Name", (g) => h("strong", {}, g.name)],
    ["Members", (g) => chips((g.members || []).map(appLabel), "none")],
  ],
  form: (g) => {
    const name = textField("Name", g.name, { required: true, placeholder: "streaming" });
    const members = appPicker("Members", g.members, { groups: false, none: "Pick at least one application or category." });
    return form([name, members], () => ({ name: name.get(), members: members.get() }));
  },
});

const routeSpec = (live) => ({
  key: "routes", title: "Static routes", singular: "route",
  note: "Installed at commit; policy still decides what may pass. A 0.0.0.0/0 route in the default VRF overrides the deployment gateway; the management default comes only from the deployment settings.",
  blank: () => ({ name: "", destination: "", gateway: "", interface: "", table: "", vrf: "", next_vrf: "" }),
  columns: [
    ["Name", (r) => h("strong", {}, r.name)],
    ["Destination", (r) => h("span", { class: "mono" }, r.destination)],
    ["VRF", (r) => r.vrf || (r.table === "mgmt" ? "mgmt" : "default")],
    ["Next hop", (r) => (r.next_vrf ? ["vrf ", h("strong", {}, r.next_vrf)] : h("span", { class: "mono" }, r.gateway))],
    ["Interface", (r) => r.interface || h("span", { class: "muted" }, "auto")],
    ["State", (r) => {
      const s = live.find((x) => x.name === r.name);
      if (!s) return h("span", { class: "muted" }, "not committed");
      return s.installed ? h("span", { class: "action-allow" }, "installed")
        : [h("span", { class: "action-deny" }, "not installed"), s.error ? h("div", { class: "muted small" }, s.error) : null];
    }],
  ],
  form: (r) => {
    const f = {
      name: textField("Name", r.name, { required: true }),
      destination: textField("Destination", r.destination, { required: true, placeholder: "10.20.0.0/16" }),
      gateway: textField("Gateway", r.gateway, { placeholder: "10.10.1.254", hint: "Not needed with a next VRF" }),
      vrf: selectField("VRF", r.vrf || (r.table === "mgmt" ? "mgmt" : "default"),
        [{ value: "default", label: "default (traffic through the firewall)" }, { value: "mgmt", label: "mgmt (the firewall's own management)" }, ...vrfNames()]),
      next: selectField("Next VRF", r.next_vrf || "", [{ value: "", label: "(none)" }, ...vrfNames()], { hint: "Leak: route the destination on in another VRF" }),
      iface: selectField("Interface", r.interface || "", [{ value: "", label: "(auto: from the gateway)" }, ...state.cand.interfaces.map((i) => i.name)],
        { hint: "Usually leave on auto" }),
    };
    return form(Object.values(f), () => ({
      name: f.name.get(), destination: f.destination.get(), gateway: f.gateway.get(), interface: f.iface.get(),
      table: "", vrf: f.vrf.get() === "default" ? "" : f.vrf.get(), next_vrf: f.next.get(),
    }));
  },
});

async function pageNetwork() {
  const [live, devs, nics, arp] = await Promise.all([api("GET", "routes").catch(() => []), api("GET", "netdev").catch(() => []),
    api("GET", "nics").catch(() => []), api("GET", "arp").then((v) => ({ ok: v }), (e) => ({ err: e.message }))]);
  const sys = state.cand.system;
  const host = textField("Hostname", sys.hostname);
  const mgmt = textField("Management interface", sys.mgmt_interface, { hint: "Never filtered by policy" });
  const save = h("button", { class: "primary", onclick: async () => {
    const cfg = clone(state.cand);
    cfg.system = { hostname: host.get(), mgmt_interface: mgmt.get() };
    try { await saveCandidate(cfg, "System settings saved to the candidate."); } catch (e) { toast(e.message); }
  } }, "Save");
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Interfaces")),
    h("section", { class: "panel" }, h("h2", {}, "System"), h("div", { class: "row" }, host.node, mgmt.node, save)),
    listSection(zoneSpec()), listSection(vrfSpec(devs)), listSection(ifaceSpec(devs, nics)), listSection(routeSpec(live || [])),
    liveNetwork(nics || [], arp));
}

// liveNetwork shows configured NIC addresses and the ARP table (CLI: show
// interfaces, show arp).
function liveNetwork(nics, arp) {
  const ok = (s) => /REACHABLE|STALE|DELAY|PROBE|PERMANENT|NOARP/.test(s);
  return h("section", { class: "panel" },
    h("div", { class: "page-head" }, h("h2", {}, "Live: addresses and ARP"), h("span", { class: "spacer" }), h("button", { onclick: route }, "Refresh")),
    nics.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Interface"), h("th", {}, "Configured address"), h("th", {}, "State"))),
      h("tbody", {}, nics.map((n) => h("tr", {}, h("td", {}, n.name), h("td", { class: "mono" }, n.address === "trunk-only" ? "none (trunk)" : n.address),
        h("td", {}, n.applied ? h("span", { class: "action-allow" }, "applied") : h("span", { class: "action-deny" }, "not applied: " + (n.error || "")))))))) : null,
    arp.err ? h("p", { class: "muted" }, arp.err)
      : arp.ok.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Address"), h("th", {}, "Interface"), h("th", {}, "MAC"), h("th", {}, "State"))),
        h("tbody", {}, arp.ok.map((n) => h("tr", {}, h("td", { class: "mono" }, n.address), h("td", {}, n.interface),
          h("td", { class: "mono" }, n.mac || "—"), h("td", {}, h("span", { class: ok(n.state) ? "action-allow" : "action-deny" }, n.state)))))))
        : h("p", { class: "empty" }, "The ARP table is empty (or isn't available here)."));
}

async function pageTags() {
  const rows = await api("GET", "tags");
  const ip = textField("IP address", "", { placeholder: "10.10.1.50" });
  const tags = textField("Tags", "", { placeholder: "quarantine", hint: "Comma-separated" });
  const ttl = textField("Expires after (minutes)", "", { placeholder: "blank = never" });
  const add = h("button", { class: "primary", onclick: async () => {
    try {
      await api("POST", "tags/register", { ip: ip.get(), tags: tags.get().split(",").map((s) => s.trim()).filter(Boolean), ttl: Math.round(Number(ttl.get() || 0) * 60) });
      toast("Registered. It applies now, with no commit.");
      await refresh(); route();
    } catch (e) { toast(e.message); }
  } }, "Register");
  const fmt = (s) => (s >= 3600 ? `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m` : s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`);
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Tags"), h("span", { class: "muted small" }, "Tag registrations change dynamic address groups immediately and cut the host's existing sessions.")),
    can("tags", "change") ? h("section", { class: "panel" }, h("h2", {}, "Register a host"), h("div", { class: "row" }, ip.node, tags.node, ttl.node, add)) : null,
    h("section", { class: "panel" }, h("h2", {}, "Registrations"),
      rows.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "IP"), h("th", {}, "Tag"), h("th", {}, "Expires"), h("th", {}, ""))),
        h("tbody", {}, rows.map((r) => h("tr", {},
          h("td", { class: "mono" }, r.ip), h("td", {}, h("span", { class: "chip" }, r.tag)),
          h("td", {}, r.expires ? `in ${fmt(r.remaining_seconds)}` : h("span", { class: "muted" }, "never")),
          h("td", { class: "actions" }, !can("tags", "change") ? null : h("button", { class: "link danger", onclick: () => confirmDialog(`Unregister ${r.ip} from ${r.tag}?`, "It leaves the tag's address group immediately.", async () => {
            await api("POST", "tags/unregister", { ip: r.ip, tags: [r.tag] }); await refresh(); route(); toast("Unregistered.");
          }, "Unregister") }, "Unregister"))))))) : h("p", { class: "empty" }, "No hosts are registered. All quiet at the border.")));
}

async function pageRevisions() {
  const r = await api("GET", "revisions");
  const view = async (n) => {
    const rev = await api("GET", "revisions/" + n);
    modal(`Revision ${n}`, h("pre", { class: "block" }, rev.yaml), { submit: null, wide: true });
  };
  const rollback = (n) => confirmDialog(`Roll back to revision ${n}?`,
    `Revision ${n}'s config is committed again as a new revision. Uncommitted changes in the candidate are replaced.`,
    async () => { const res = await api("POST", "rollback", { revision: n }); await refresh(); route(); toast(`Rolled back: revision ${res.revision.n} is running.`); }, "Roll back");
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Revisions")),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "#"), h("th", {}, "When"), h("th", {}, "Author"), h("th", {}, "Message"), h("th", {}, ""))),
      h("tbody", {}, r.revisions.map((v) => h("tr", {},
        h("td", {}, h("strong", {}, v.n), v.n === r.running ? h("span", { class: "chip" }, "running") : null),
        h("td", {}, new Date(v.time).toLocaleString()), h("td", {}, v.author), h("td", {}, v.message || h("span", { class: "muted" }, "—")),
        h("td", { class: "actions" }, h("button", { class: "link", onclick: () => view(v.n) }, "View"),
          v.n !== r.running && can("revisions", "change") ? h("button", { class: "link", onclick: () => rollback(v.n) }, "Roll back") : null)))))));
}

// ---- routing ---------------------------------------------------------------
function textArea(label, value, opts = {}) {
  const ta = h("textarea", { rows: opts.rows || 4, placeholder: opts.placeholder || "" });
  ta.value = value || "";
  return { node: h("label", {}, label, opts.hint ? h("span", { class: "hint" }, opts.hint) : null, ta), get: () => ta.value };
}

const plistNames = () => state.cand.prefix_lists.map((p) => p.name);

const routingSpec = () => ({
  key: "routing", title: "Protocols", singular: "routing entry",
  note: "One entry per VRF that runs BGP and/or OSPF.",
  blank: () => ({ name: "default", router_id: "", bgp_asn: 0, bgp_networks: [], bgp_redistribute: [], ospf: false, ospf_redistribute: [] }),
  columns: [
    ["VRF", (r) => h("strong", {}, r.name)],
    ["Router ID", (r) => h("span", { class: "mono" }, r.router_id)],
    ["BGP", (r) => (r.bgp_asn ? [`AS ${r.bgp_asn}`, " ", r.bgp_networks.length ? chips(r.bgp_networks) : null] : h("span", { class: "muted" }, "off"))],
    ["OSPF", (r) => (r.ospf ? "on" : h("span", { class: "muted" }, "off"))],
    ["Redistribute", (r) => [r.bgp_redistribute?.length ? ["into BGP: ", chips(r.bgp_redistribute)] : null, r.ospf_redistribute?.length ? [" into OSPF: ", chips(r.ospf_redistribute)] : null]],
  ],
  form: (r) => {
    const f = {
      name: selectField("VRF", r.name, ["default", ...vrfNames()]),
      rid: textField("Router ID", r.router_id, { required: true, placeholder: "10.10.1.1", hint: "Usually one of the firewall's addresses" }),
      asn: textField("BGP AS number", r.bgp_asn ? String(r.bgp_asn) : "", { placeholder: "empty: no BGP" }),
      nets: listField("BGP networks to announce", r.bgp_networks, "10.10.0.0/16, 172.16.0.0/12"),
      bred: multiField("Redistribute into BGP", r.bgp_redistribute, ["connected", "static", "ospf"], { noAny: true, hint: "Ctrl/Cmd-click; none for nothing" }),
      ospf: checkField("Run OSPF in this VRF", r.ospf),
      ored: multiField("Redistribute into OSPF", r.ospf_redistribute, ["connected", "static", "bgp"], { noAny: true, hint: "Ctrl/Cmd-click; none for nothing" }),
    };
    return form(Object.values(f), () => ({
      name: f.name.get(), router_id: f.rid.get(), bgp_asn: Number(f.asn.get() || 0), bgp_networks: f.nets.get(),
      bgp_redistribute: f.bred.get(), ospf: f.ospf.get(), ospf_redistribute: f.ored.get(),
    }));
  },
});

const bgpNeighborSpec = () => ({
  key: "bgp_neighbors", title: "BGP neighbors", singular: "BGP neighbor",
  blank: () => ({ name: "", vrf: "", address: "", remote_as: 0, description: "", import: "", export: "", next_hop_self: false }),
  columns: [
    ["Name", (n) => h("strong", {}, n.name)],
    ["VRF", (n) => n.vrf || "default"],
    ["Address", (n) => h("span", { class: "mono" }, n.address)],
    ["Remote AS", (n) => String(n.remote_as)],
    ["Filters", (n) => [n.import ? ["in: ", h("span", { class: "chip" }, n.import)] : null, n.export ? [" out: ", h("span", { class: "chip" }, n.export)] : null]],
    ["Description", (n) => n.description || ""],
  ],
  form: (n) => {
    const opt = [{ value: "", label: "(none: everything)" }, ...plistNames()];
    const f = {
      name: textField("Name", n.name, { required: true, placeholder: "upstream" }),
      vrf: selectField("VRF", n.vrf || "", [{ value: "", label: "default" }, ...vrfNames()]),
      addr: textField("Address", n.address, { required: true, placeholder: "192.0.2.1" }),
      ras: textField("Remote AS", n.remote_as ? String(n.remote_as) : "", { required: true, placeholder: "64500", hint: "Our own AS for iBGP" }),
      desc: textField("Description", n.description),
      imp: selectField("Import filter", n.import || "", opt, { hint: "Prefix list for routes received" }),
      exp: selectField("Export filter", n.export || "", opt, { hint: "Prefix list for routes sent" }),
      nhs: checkField("Next hop self (iBGP)", n.next_hop_self),
    };
    return form(Object.values(f), () => ({
      name: f.name.get(), vrf: f.vrf.get(), address: f.addr.get(), remote_as: Number(f.ras.get() || 0), description: f.desc.get(),
      import: f.imp.get(), export: f.exp.get(), next_hop_self: f.nhs.get(),
    }));
  },
});

const ospfIfSpec = () => ({
  key: "ospf_interfaces", title: "OSPF interfaces", singular: "OSPF interface",
  blank: () => ({ name: "", area: "0", cost: 0, passive: false }),
  columns: [
    ["Interface", (o) => h("strong", {}, o.name)],
    ["Area", (o) => o.area],
    ["Cost", (o) => (o.cost ? String(o.cost) : h("span", { class: "muted" }, "auto"))],
    ["Passive", (o) => (o.passive ? "yes" : "")],
  ],
  form: (o) => {
    const f = {
      name: selectField("Interface", o.name, state.cand.interfaces.map((i) => i.name).filter((n) => n !== state.cand.system.mgmt_interface)),
      area: textField("Area", o.area, { required: true, placeholder: "0 or 0.0.0.0" }),
      cost: textField("Cost", o.cost ? String(o.cost) : "", { placeholder: "auto" }),
      passive: checkField("Passive: announce the subnet, form no adjacencies", o.passive),
    };
    return form(Object.values(f), () => ({ name: f.name.get(), area: f.area.get(), cost: Number(f.cost.get() || 0), passive: f.passive.get() }));
  },
});

const prefixListSpec = () => ({
  key: "prefix_lists", title: "Prefix lists", singular: "prefix list",
  note: "Filters for BGP neighbors. Entries are checked in order; anything unmatched is denied.",
  blank: () => ({ name: "", entries: [] }),
  columns: [["Name", (p) => h("strong", {}, p.name)], ["Entries", (p) => h("div", { class: "mono small" }, p.entries.map((e) => h("div", {}, e)))]],
  form: (p) => {
    const name = textField("Name", p.name, { required: true, placeholder: "from-upstream" });
    const ents = textArea("Entries, one per line", p.entries.join("\n"), { placeholder: "permit 10.0.0.0/8 le 24\ndeny any", hint: "permit|deny PREFIX|any [ge N] [le N]" });
    return form([name, ents], () => ({ name: name.get(), entries: ents.get().split("\n").map((s) => s.trim()).filter(Boolean) }));
  },
});

async function pageRouting() {
  const get = (what) => api("GET", "routing/" + what).then((v) => ({ ok: v }), (e) => ({ err: e.message }));
  const [bgp, ospf, rib] = await Promise.all([get("bgp"), get("ospf"), get("routes")]);
  const stateClass = (s) => (/^(Established|Full)/.test(s) ? "action-allow" : "action-deny");
  const live = (title, res, head, row, empty) => h("section", { class: "panel" }, h("h2", {}, title),
    res.err ? h("p", { class: "muted" }, res.err)
      : res.ok.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, head.map((t) => h("th", {}, t)))), h("tbody", {}, res.ok.map(row))))
        : h("p", { class: "empty" }, empty));
  const dyn = rib.ok ? { ok: rib.ok.filter((r) => r.protocol === "bgp" || r.protocol === "ospf") } : rib;
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Routing"), h("span", { class: "spacer" }), h("button", { onclick: route }, "Refresh")),
    h("p", { class: "tagline" }, "Talking to the neighbours: BGP and OSPF."),
    live("BGP neighbors", bgp, ["VRF", "Neighbor", "Remote AS", "State", "Up/down", "Received", "Sent"],
      (p) => h("tr", {}, h("td", {}, p.vrf), h("td", { class: "mono" }, p.address), h("td", {}, String(p.remote_as)),
        h("td", {}, h("span", { class: stateClass(p.state) }, p.state)), h("td", {}, p.uptime), h("td", {}, String(p.prefixes_received)), h("td", {}, String(p.prefixes_sent))),
      "No BGP neighbors configured."),
    live("OSPF neighbors", ospf, ["VRF", "Neighbor ID", "State", "Address", "Interface"],
      (n) => h("tr", {}, h("td", {}, n.vrf), h("td", { class: "mono" }, n.router_id), h("td", {}, h("span", { class: stateClass(n.state) }, n.state)), h("td", { class: "mono" }, n.address), h("td", {}, n.interface)),
      "No OSPF neighbors."),
    live("Learned routes", dyn, ["VRF", "Prefix", "Protocol", "Next hop", "Interface", "Best"],
      (r) => h("tr", {}, h("td", {}, r.vrf), h("td", { class: "mono" }, r.prefix), h("td", {}, r.protocol), h("td", { class: "mono" }, r.next_hop || "connected"), h("td", {}, r.interface), h("td", {}, r.selected ? "yes" : "")),
      "No routes learned over BGP or OSPF."),
    listSection(routingSpec()), listSection(bgpNeighborSpec()), listSection(ospfIfSpec()), listSection(prefixListSpec()));
}

// ---- DHCP ------------------------------------------------------------------
const dataIfaces = () => state.cand.interfaces.map((i) => i.name).filter((n) => n !== state.cand.system.mgmt_interface);
const dhcpIfaces = () => state.cand.dhcp_servers.map((s) => s.name);
const secs = (n) => (n % 86400 === 0 ? `${n / 86400}d` : n % 3600 === 0 ? `${n / 3600}h` : n % 60 === 0 ? `${n / 60}m` : `${n}s`);

const dhcpServerSpec = () => ({
  key: "dhcp_servers", title: "DHCP servers", singular: "DHCP server",
  note: "One per interface. The interface needs its address set on the Network page; clients get it as their gateway.",
  blank: () => ({ name: "", range: "", gateway: "", dns: [], domain: "", ntp: [], lease_time: 0, options: [] }),
  columns: [
    ["Interface", (s) => h("strong", {}, s.name)],
    ["Range", (s) => h("span", { class: "mono" }, s.range)],
    ["Gateway", (s) => (s.gateway ? h("span", { class: "mono" }, s.gateway) : h("span", { class: "muted" }, "interface address"))],
    ["DNS", (s) => (s.dns?.length ? h("span", { class: "mono" }, s.dns.join(", ")) : h("span", { class: "muted" }, "firewall's"))],
    ["Domain", (s) => s.domain || ""],
    ["Lease", (s) => secs(s.lease_time || 86400)],
    ["Options", (s) => (s.options?.length ? chips(s.options) : "")],
  ],
  form: (s) => {
    const f = {
      name: selectField("Interface", s.name, dataIfaces()),
      range: textField("Range", s.range, { required: true, placeholder: "192.168.150.100-192.168.150.199", hint: "First and last address to hand out" }),
      gw: textField("Gateway", s.gateway, { placeholder: "empty: the interface's address" }),
      dns: listField("DNS servers", s.dns, "empty: the firewall's own DNS servers"),
      domain: textField("Domain", s.domain, { placeholder: "home.example" }),
      ntp: listField("NTP servers", s.ntp, "optional"),
      lease: textField("Lease time (seconds)", s.lease_time ? String(s.lease_time) : "", { placeholder: "86400 (a day)" }),
      opts: textArea("More options, one per line", (s.options || []).join("\n"), { rows: 3, placeholder: "66=tftp.home.example\n150=0x0a000001", hint: "CODE=VALUE; 0x... sends raw hex" }),
    };
    return form(Object.values(f), () => ({
      name: f.name.get(), range: f.range.get(), gateway: f.gw.get(), dns: f.dns.get(), domain: f.domain.get(), ntp: f.ntp.get(),
      lease_time: Number(f.lease.get() || 0), options: f.opts.get().split("\n").map((x) => x.trim()).filter(Boolean),
    }));
  },
});

const dhcpReservationSpec = () => ({
  key: "dhcp_reservations", title: "Reservations", singular: "reservation",
  note: "A device (by MAC address) always gets the same address. It may be inside or outside the range.",
  blank: () => ({ name: "", interface: dhcpIfaces()[0] || "", mac: "", address: "" }),
  columns: [
    ["Name", (r) => h("strong", {}, r.name)],
    ["Interface", (r) => r.interface],
    ["MAC", (r) => h("span", { class: "mono" }, r.mac)],
    ["Address", (r) => h("span", { class: "mono" }, r.address)],
  ],
  form: (r) => {
    const f = {
      name: textField("Name", r.name, { required: true, placeholder: "printer" }),
      iface: selectField("Interface", r.interface, dhcpIfaces(), { hint: "One with a DHCP server" }),
      mac: textField("MAC address", r.mac, { required: true, placeholder: "52:54:00:12:34:56" }),
      addr: textField("Address", r.address, { required: true, placeholder: "192.168.150.20" }),
    };
    return form(Object.values(f), () => ({ name: f.name.get(), interface: f.iface.get(), mac: f.mac.get(), address: f.addr.get() }));
  },
});

async function pageDHCP() {
  const st = await api("GET", "dhcp").catch((e) => ({ err: e.message, servers: [] }));
  const leases = st.servers.length && st.running ? await api("GET", "dhcp/leases").then((v) => ({ ok: v }), (e) => ({ err: e.message })) : { ok: [] };
  const kea = !st.servers.length ? null
    : !st.installed ? h("p", { class: "muted" }, "The DHCP server (Kea) isn't installed yet; an upgrade installs it in the background.")
      : st.running ? h("p", {}, h("span", { class: "action-allow" }, "Running"), " Kea DHCP server")
        : h("p", {}, h("span", { class: "action-deny" }, "Not running"), " Kea DHCP server: check the system log.");
  const stateClass = (s) => (s === "active" ? "action-allow" : "action-deny");
  const fmt = (t) => new Date(t).toLocaleString();
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "DHCP"), h("span", { class: "spacer" }), h("button", { onclick: route }, "Refresh")),
    h("p", { class: "tagline" }, "Every newcomer gets an address and directions to the exit."),
    h("section", { class: "panel" }, h("h2", {}, "Live"), kea,
      st.servers.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Interface", "Network", "Range", "Gateway", "DNS", "Active leases"].map((t) => h("th", {}, t)))),
        h("tbody", {}, st.servers.map((s) => h("tr", {}, h("td", {}, h("strong", {}, s.interface)), h("td", { class: "mono" }, s.network),
          h("td", { class: "mono" }, s.range), h("td", { class: "mono" }, s.gateway),
          h("td", { class: "mono" }, s.dns.length ? s.dns.join(", ") + (s.dns_default ? " (firewall's)" : "") : h("span", { class: "action-deny" }, "none")),
          h("td", {}, String(s.leases)))))))
        : h("p", { class: "empty" }, "No DHCP servers in the running config."),
      h("h3", {}, "Leases"),
      leases.err ? h("p", { class: "muted" }, leases.err)
        : leases.ok.length ? h("div", { class: "table-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, ["Interface", "Address", "MAC", "Hostname", "State", "Expires", "Reservation"].map((t) => h("th", {}, t)))),
          h("tbody", {}, leases.ok.map((l) => h("tr", {}, h("td", {}, l.interface), h("td", { class: "mono" }, l.address), h("td", { class: "mono" }, l.mac),
            h("td", {}, l.hostname || ""), h("td", {}, h("span", { class: stateClass(l.state) }, l.state)), h("td", {}, fmt(l.expires)), h("td", {}, l.reserved || ""))))))
          : h("p", { class: "empty" }, "No leases yet.")),
    listSection(dhcpServerSpec()), listSection(dhcpReservationSpec()));
}

// ---- applications (App Identification) ---------------------------------------------------
const fmtBytes = (n) => {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(1) : n} ${u[i]}`;
};
state.apps = { q: "" };

// stateBadge shows what an inspection engine does to traffic now.
function stateBadge(state) {
  const cls = { inspecting: "action-allow", classifying: "action-allow", decrypting: "action-allow", observing: "action-reset", busy: "action-reset", loading: "action-reset", starting: "action-deny", unavailable: "action-deny", "no-ca": "action-deny" }[state] || "muted";
  return h("span", { class: cls }, state ? state[0].toUpperCase() + state.slice(1) : "?");
}

async function pageApps() {
  const st = await api("GET", "apps");
  const status = !st.enabled ? h("span", { class: "muted" }, "Off")
    : st.running ? h("span", { class: "action-allow" }, "Running") : h("span", { class: "action-deny" }, "Not running");
  const max = Math.max(1, ...st.apps.map((a) => a.bytes));
  const seen = st.apps.length ? h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Application", "Category", "Connections", "Bytes", "", "Last seen"].map((t) => h("th", {}, t)))),
    h("tbody", {}, st.apps.map((a) => h("tr", {},
      h("td", {}, h("button", { class: "link", title: "Show its log entries", onclick: () => { state.logs.kind = "traffic"; state.logs.q = a.name; location.hash = "#logs"; } }, a.name)),
      h("td", {}, a.category || ""),
      h("td", { class: "mono" }, String(a.flows)),
      h("td", { class: "mono" }, fmtBytes(a.bytes)),
      h("td", { class: "bar-cell" }, (() => {
        // Set through the CSSOM: the UI's CSP refuses inline style attributes.
        const bar = h("span", { class: "bar", title: `${Math.round((a.bytes / max) * 100)}% of the top application` });
        bar.style.width = `${Math.max(2, Math.round((a.bytes / max) * 100))}%`;
        return bar;
      })()),
      h("td", { class: "time" }, fmtTime(a.last_seen)))))))
    : h("p", { class: "empty" }, st.note || "Nothing seen yet.");

  const catView = h("div");
  const search = h("input", { value: state.apps.q, placeholder: "name or category, e.g. video", "aria-label": "Search the catalog" });
  const loadCat = async () => {
    try {
      const apps = await api("GET", "apps/catalog?q=" + encodeURIComponent(state.apps.q));
      catView.replaceChildren(h("p", { class: "muted small" }, `${apps.length} applications`),
        h("div", { class: "table-wrap cat-list" }, h("table", {},
          h("thead", {}, h("tr", {}, h("th", {}, "Application"), h("th", {}, "Category"))),
          h("tbody", {}, apps.map((a) => h("tr", {}, h("td", {}, a.name), h("td", {}, a.category)))))));
    } catch (e) {
      catView.replaceChildren(errorBox(e));
    }
  };
  search.addEventListener("keydown", (e) => { if (e.key === "Enter") { state.apps.q = search.value.trim(); loadCat(); } });
  await loadCat();
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Applications"), h("span", { class: "spacer" }), h("button", { onclick: route }, "Refresh")),
    h("p", { class: "tagline" }, "Papers, please: every connection is named at the border."),
    h("section", { class: "panel" },
      h("h2", {}, "Seen since App Identification started"),
      h("p", {}, "App Identification: ", status, st.running ? ` · ${st.active_flows} connections being identified` : "",
        st.note && st.apps.length ? h("span", { class: "muted" }, " · " + st.note) : null),
      h("p", {}, "Traffic: ", stateBadge(st.state), h("span", { class: "muted" }, " · " + (st.state_detail || ""))),
      seen,
      h("p", { class: "muted small" }, "Counted when connections end. Each rule's own connections, with their application, are in Logs (end entries) for rules with logging on.")),
    h("section", { class: "panel" },
      h("h2", {}, "What App Identification can identify"),
      h("div", { class: "row" }, h("label", {}, "Search", search), h("button", { onclick: () => { state.apps.q = search.value.trim(); loadCat(); } }, "Search")),
      catView));
}

// ---- logs ------------------------------------------------------------------
state.logs = { kind: "traffic", q: "", n: 200, auto: false, cols: null, colDefs: null, picking: false, tcols: null, tcolDefs: null };

// Traffic log columns: chosen per browser (a viewer preference, not config).
const COLS_KEY = "sjb.logs.columns";
function loadCols(defaults, key = COLS_KEY) {
  try {
    const v = JSON.parse(localStorage.getItem(key) || "null");
    if (Array.isArray(v) && v.length) return v;
  } catch (e) { /* storage unavailable: use the defaults */ }
  return defaults.slice();
}
function saveCols(cols, key = COLS_KEY) {
  try { localStorage.setItem(key, JSON.stringify(cols)); } catch (e) { /* not remembered, still applied */ }
}
const THREAT_COLS_KEY = "sjb.logs.threat-columns";
const DECRYPT_COLS_KEY = "sjb.logs.decryption-columns";

async function pageLogs() {
  const L = state.logs;
  if (!L.colDefs) {
    const c = await api("GET", "logs/traffic/columns");
    L.colDefs = c.columns;
    L.colDefault = c.default;
    L.fields = c.fields;
    const known = new Set(c.columns.map((x) => x.name));
    L.cols = loadCols(c.default).filter((n) => known.has(n));
    if (!L.cols.length) L.cols = c.default.slice();
    L.tcolDefs = c.threat_columns;
    L.tcolDefault = c.threat_default;
    const tknown = new Set(c.threat_columns.map((x) => x.name));
    L.tcols = loadCols(c.threat_default, THREAT_COLS_KEY).filter((n) => tknown.has(n));
    if (!L.tcols.length) L.tcols = c.threat_default.slice();
    L.dcolDefs = c.decryption_columns;
    L.dcolDefault = c.decryption_default;
    const dknown = new Set(c.decryption_columns.map((x) => x.name));
    L.dcols = loadCols(c.decryption_default, DECRYPT_COLS_KEY).filter((n) => dknown.has(n));
    if (!L.dcols.length) L.dcols = c.decryption_default.slice();
  }
  // The column picker works on the traffic or the threat columns.
  const threat = L.kind === "threat";
  const dec = L.kind === "decryption";
  const C = threat
    ? { defs: L.tcolDefs, def: L.tcolDefault, get: () => L.tcols, set: (v) => { L.tcols = v; saveCols(v, THREAT_COLS_KEY); } }
    : dec ? { defs: L.dcolDefs, def: L.dcolDefault, get: () => L.dcols, set: (v) => { L.dcols = v; saveCols(v, DECRYPT_COLS_KEY); } }
    : { defs: L.colDefs, def: L.colDefault, get: () => L.cols, set: (v) => { L.cols = v; saveCols(v); } };
  const view = h("div");
  let rows = [];
  const draw = () => view.replaceChildren(L.kind === "traffic" ? trafficTable(rows) : threat ? threatTable(rows) : dec ? decryptionTable(rows) : systemTable(rows));
  const load = async () => {
    try {
      rows = await api("GET", `logs/${L.kind}?n=${L.n}&q=${encodeURIComponent(L.q)}`);
      draw();
    } catch (e) {
      view.replaceChildren(h("div", { class: "panel" }, errorBox(e)));
    }
  };
  const tab = (kind, label) => h("button", { class: L.kind === kind ? "active" : "", onclick: () => { if (L.kind !== kind) { L.kind = kind; L.q = ""; } route(); } }, label);
  const search = h("input", { value: L.q, placeholder: L.kind === "traffic" ? "e.g. zone = inside and dst = 4.2.2.2" : threat ? "e.g. severity = critical and action = block" : dec ? "e.g. decision = learned or server_name ~ example.com" : "e.g. source = sshd and message ~ failed", "aria-label": "Search the log", class: "log-query" });
  // Query help: fields of this log and the operators.
  const help = h("div", { class: "panel query-help" + (L.helping ? "" : " hidden") },
    h("p", {}, h("strong", {}, "Search: "), "plain words match anywhere; or ", h("code", {}, "field op value"),
      " conditions joined with ", h("code", {}, "and"), ", ", h("code", {}, "or"), ", ", h("code", {}, "not"), " and ( ).",
      " Click any value in the table to add it as a condition."),
    h("p", {}, h("strong", {}, "Operators: "), h("code", {}, "="), " ", h("code", {}, "!="), " ", h("code", {}, "~"), " (contains) ",
      h("code", {}, "!~"), " ", h("code", {}, "> < >= <="), ". Addresses take an IP or CIDR (", h("code", {}, "dst = 10.0.0.0/8"),
      "); numbers a range too (", h("code", {}, "dport = 1000-2000"), ")."),
    h("p", {}, h("strong", {}, "Examples: "), (L.kind === "traffic"
      ? ["zone = inside and dst = 4.2.2.2", "app ~ tube or category = media", "action != allow and dport = 22", "type = end and bytes > 1000000"]
      : threat ? ["severity = critical", "action = block and src = 10.0.0.0/8", "signature ~ trojan", "rule = inside-out and sid = 2100498"]
      : dec ? ["decision = decrypted", "decision = learned", "server_name ~ example.com", "decision = blocked and src = 10.0.0.0/8"]
      : ["source = sshd and message ~ failed", "level = error", "source = ngfwd and message = commit"])
      .flatMap((ex, i) => [i ? " · " : null, h("button", { class: "link mono", onclick: () => { L.q = ex; route(); } }, ex)])),
    h("div", { class: "field-grid" }, ((L.fields && L.fields[L.kind]) || []).map((f) => h("div", {}, h("code", {}, f.name), " ", h("span", { class: "muted small" }, f.help)))));
  search.addEventListener("keydown", (e) => { if (e.key === "Enter") { L.q = search.value.trim(); load(); } });
  const count = h("select", { "aria-label": "How many entries", onchange: (e) => { L.n = Number(e.target.value); load(); } },
    [50, 200, 1000].map((n) => h("option", { value: n, selected: n === L.n }, `${n} newest`)));
  const auto = h("input", { type: "checkbox", checked: L.auto });
  auto.addEventListener("change", () => {
    L.auto = auto.checked;
    clearInterval(state.logTimer);
    if (L.auto) state.logTimer = setInterval(load, 5000);
  });
  if (L.auto) state.logTimer = setInterval(load, 5000);
  // Column picker (traffic and threat): checkboxes in display order.
  const picker = h("div", { class: "panel col-picker" + (L.picking && L.kind !== "system" ? "" : " hidden") },
    h("div", { class: "row" }, h("strong", {}, "Columns"), h("span", { class: "spacer" }),
      h("button", { class: "link", onclick: () => { C.set(C.def.slice()); syncBoxes(); draw(); } }, "Reset to default")),
    h("div", { class: "col-grid" }, C.defs.map((c) => {
      const box = h("input", { type: "checkbox", checked: C.get().includes(c.name), "data-col": c.name });
      box.addEventListener("change", () => {
        const on = new Set([...C.get().filter((n) => n !== c.name), ...(box.checked ? [c.name] : [])]);
        if (!on.size) { box.checked = true; return; } // keep at least one
        C.set(C.defs.map((d) => d.name).filter((n) => on.has(n)));
        draw();
      });
      return h("label", { class: "check", title: c.help }, box, c.title);
    })));
  const syncBoxes = () => picker.querySelectorAll("input[data-col]").forEach((b) => { b.checked = C.get().includes(b.dataset.col); });
  const colsBtn = L.kind !== "system" ? h("button", { "aria-expanded": String(L.picking), onclick: (e) => {
    L.picking = !L.picking;
    picker.classList.toggle("hidden", !L.picking);
    e.currentTarget.setAttribute("aria-expanded", String(L.picking));
  } }, "Columns") : null;
  await load();
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Logs"),
      h("span", { class: "seg" }, tab("traffic", "Data plane (traffic)"), tab("threat", "Threats (IPS)"), tab("decryption", "Decryption (TLS)"), tab("system", "Management (system)"))),
    h("p", { class: "tagline" }, "The guard's notebook, newest entries first."),
    h("div", { class: "row panel" },
      h("label", {}, "Search", search),
      h("label", {}, "Show", count),
      h("button", { onclick: () => { L.q = search.value.trim(); load(); } }, "Search"),
      h("button", { class: "link", onclick: () => { L.q = ""; route(); } }, "Clear"),
      h("button", { class: "link", "aria-expanded": String(!!L.helping), onclick: (e) => {
        L.helping = !L.helping;
        help.classList.toggle("hidden", !L.helping);
        e.currentTarget.setAttribute("aria-expanded", String(L.helping));
      } }, "Query help"),
      h("label", { class: "check" }, auto, "Refresh every 5 seconds"),
      colsBtn),
    help,
    L.kind !== "system" ? picker : null,
    view);
}

const fmtTime = (t) => new Date(t).toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });

// addCondition appends "field = value" to a log query (quoting the value
// when needed), replacing nothing the operator already typed.
function addCondition(q, field, v) {
  const val = /^[\w.\/:-]+$/.test(String(v)) ? String(v) : `"${String(v).replace(/"/g, "")}"`;
  const cond = `${field} = ${val}`;
  q = (q || "").trim();
  if (!q) return cond;
  if (q.includes(cond)) return q;
  return /\bor\b/i.test(q) ? `(${q}) and ${cond}` : `${q} and ${cond}`;
}

function trafficTable(rows) {
  if (!rows.length) {
    return h("p", { class: "empty panel" }, "Nothing logged yet. Only rules with logging on write here: turn on Log for a rule on the Policy page, or in the CLI: set rule NAME log yes.");
  }
  const L = state.logs;
  const defs = new Map(L.colDefs.map((c) => [c.name, c]));
  const filterBy = (field, v) => (v === undefined || v === null || v === "" ? "" :
    h("button", { class: "link", title: `Add ${field} = ${v} to the search`, onclick: () => { state.logs.q = addCondition(state.logs.q, field, v); route(); } }, String(v)));
  const cell = {
    time: (r) => h("td", { class: "time" }, fmtTime(r.time)),
    rule: (r) => h("td", {}, filterBy("rule", r.rule)),
    action: (r) => h("td", {}, h("span", { class: "action-" + r.action }, r.action)),
    from: (r) => h("td", {}, filterBy("from", r.from)),
    to: (r) => h("td", {}, filterBy("to", r.to)),
    in: (r) => h("td", {}, r.in || ""),
    out: (r) => h("td", {}, r.out || ""),
    src: (r) => h("td", { class: "mono" }, filterBy("src", r.src)),
    sport: (r) => h("td", { class: "mono" }, filterBy("sport", r.sport)),
    dst: (r) => h("td", { class: "mono" }, filterBy("dst", r.dst)),
    dport: (r) => h("td", { class: "mono" }, filterBy("dport", r.dport)),
    proto: (r) => h("td", {}, r.proto),
    app: (r) => h("td", {}, r.app ? filterBy("app", r.app) : h("span", { class: "muted", title: r.type === "start" ? "Known when the connection ends (an end entry)" : "Not identified" }, "—")),
    type: (r) => h("td", {}, r.type || ""),
    category: (r) => h("td", {}, r.category || ""),
    bytes: (r) => h("td", { class: "mono" }, r.bytes ? fmtBytes(r.bytes) : ""),
    packets: (r) => h("td", { class: "mono" }, r.packets ? String(r.packets) : ""),
    duration: (r) => h("td", { class: "mono" }, r.type === "end" ? `${(r.duration || 0).toFixed(1)} s` : ""),
    len: (r) => h("td", { class: "mono" }, r.len ? String(r.len) : ""),
    ttl: (r) => h("td", { class: "mono" }, r.ttl ? String(r.ttl) : ""),
    flags: (r) => h("td", { class: "mono" }, r.flags || ""),
    icmp: (r) => h("td", { class: "mono" }, r.icmp || ""),
  };
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, L.cols.map((c) => h("th", { title: defs.get(c).help }, defs.get(c).title)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, L.cols.map((c) => cell[c](r)))))));
}

function threatTable(rows) {
  if (!rows.length) {
    return h("p", { class: "empty panel" }, "No threats logged. Rules with an IPS profile write here when a signature matches their traffic (Policy → IPS profile, or set rule NAME ips-profile default).");
  }
  const L = state.logs;
  const defs = new Map(L.tcolDefs.map((c) => [c.name, c]));
  const filterBy = (field, v) => (v === undefined || v === null || v === "" || v === 0 ? "" :
    h("button", { class: "link", title: `Add ${field} = ${v} to the search`, onclick: () => { state.logs.q = addCondition(state.logs.q, field, v); route(); } }, String(v)));
  const sevClass = { critical: "action-deny", major: "action-deny", minor: "action-reset" };
  const cell = {
    time: (r) => h("td", { class: "time" }, fmtTime(r.time)),
    rule: (r) => h("td", {}, filterBy("rule", r.rule)),
    profile: (r) => h("td", {}, filterBy("profile", r.profile)),
    action: (r) => h("td", {}, h("span", { class: r.action === "block" ? "action-deny" : "action-reset" }, r.action)),
    severity: (r) => h("td", {}, h("span", { class: sevClass[r.severity] || "muted" }, r.severity)),
    sid: (r) => h("td", { class: "mono" }, filterBy("sid", r.sid)),
    signature: (r) => h("td", {}, r.signature),
    category: (r) => h("td", {}, r.category || ""),
    app: (r) => h("td", {}, r.app ? filterBy("app", r.app) : ""),
    src: (r) => h("td", { class: "mono" }, filterBy("src", r.src)),
    sport: (r) => h("td", { class: "mono" }, filterBy("sport", r.sport)),
    dst: (r) => h("td", { class: "mono" }, filterBy("dst", r.dst)),
    dport: (r) => h("td", { class: "mono" }, filterBy("dport", r.dport)),
    proto: (r) => h("td", {}, r.proto),
    decrypted: (r) => h("td", {}, r.decrypted ? "yes" : ""),
  };
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, L.tcols.map((c) => h("th", { title: defs.get(c).help }, defs.get(c).title)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, L.tcols.map((c) => cell[c](r)))))));
}

function decryptionTable(rows) {
  if (!rows.length) {
    return h("p", { class: "empty panel" }, "Nothing logged yet. Connections that decryption rules cover write here (Policy → Decryption rules).");
  }
  const L = state.logs;
  const defs = new Map(L.dcolDefs.map((c) => [c.name, c]));
  const filterBy = (field, v) => (v === undefined || v === null || v === "" || v === 0 ? "" :
    h("button", { class: "link", title: `Add ${field} = ${v} to the search`, onclick: () => { state.logs.q = addCondition(state.logs.q, field, v); route(); } }, String(v)));
  const decClass = { decrypted: "action-allow", blocked: "action-deny", failed: "action-deny", learned: "action-reset" };
  const cell = {
    time: (r) => h("td", { class: "time" }, fmtTime(r.time)),
    rule: (r) => h("td", {}, filterBy("rule", r.rule)),
    decision: (r) => h("td", {}, h("span", { class: decClass[r.decision] || "muted" }, filterBy("decision", r.decision))),
    reason: (r) => h("td", { class: "small" }, r.reason || ""),
    server_name: (r) => h("td", {}, filterBy("server_name", r.server_name)),
    src: (r) => h("td", { class: "mono" }, filterBy("src", r.src)),
    sport: (r) => h("td", { class: "mono" }, filterBy("sport", r.sport)),
    dst: (r) => h("td", { class: "mono" }, filterBy("dst", r.dst)),
    dport: (r) => h("td", { class: "mono" }, filterBy("dport", r.dport)),
    tls: (r) => h("td", {}, r.tls || ""),
    alpn: (r) => h("td", {}, r.alpn || ""),
  };
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, L.dcols.map((c) => h("th", { title: defs.get(c).help }, defs.get(c).title)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, L.dcols.map((c) => cell[c](r)))))));
}

function systemTable(rows) {
  if (!rows.length) return h("p", { class: "empty panel" }, "No entries. A quiet day at the border.");
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Time", "Source", "Level", "Message"].map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.map((r) => h("tr", {},
      h("td", { class: "time" }, fmtTime(r.time)),
      h("td", {}, r.source),
      h("td", {}, h("span", { class: "level-" + r.level }, r.level)),
      h("td", {}, r.message, r.fields ? h("div", { class: "muted small mono" }, r.fields) : null))))));
}

async function pageIPS() {
  const st = await api("GET", "ips");
  const sig = st.signatures || {};
  const counts = sig.counts || {};
  const when = (t) => (t && !t.startsWith("0001") ? new Date(t).toLocaleString() : "never");
  const engine = st.running && st.loading ? h("span", { class: "action-reset" }, "loading")
    : st.running ? h("span", { class: "action-allow" }, "running")
    : h("span", { class: "muted" }, !st.installed ? "not installed" : st.in_use && st.enabled ? "starting" : "stopped");
  const engineSub = st.running && st.loading ? `loading the signatures${st.loaded ? ` (${st.loaded.toLocaleString()} active meanwhile)` : ""}`
    : st.running ? `${(st.loaded || 0).toLocaleString()} signatures loaded`
    : !st.installed ? "Suricata installs in the background after an upgrade"
    : !st.enabled ? "IPS off (system ips)" : !st.in_use ? "no rule uses an IPS profile" : "Suricata, IPS on";
  const btn = h("button", { class: "primary" }, "Update signatures now");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "Downloading…";
    try {
      const r = await api("POST", "ips/update");
      toast(`Signatures updated: ${r.signatures} (version ${r.version || "?"})`);
      route();
    } catch (e) { toast(e.message); btn.disabled = false; btn.textContent = "Update signatures now"; }
  });
  const gb = st.mem_total ? st.mem_total / 2 ** 30 : 0;
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "IPS"), can("ips", "change") ? btn : null),
    h("p", { class: "tagline" }, "Known troublemakers are stopped at the border."),
    h("div", { class: "cards" },
      card("Inspection", stateBadge(st.state), st.state_detail || ""),
      card("Engine", engine, engineSub),
      card("Signatures", (sig.signatures || 0).toLocaleString(), sig.source ? `${sig.source}${sig.version ? ", version " + sig.version : ""}` : "none yet"),
      card("Last update", when(sig.updated), sig.last_error ? `last attempt failed: ${sig.last_error}` : "checked daily"),
      card("Memory", gb ? `${gb.toFixed(1)} GB` : "?", gb && gb < 3.5 ? "give the VM 4 GB for the IPS" : "4 GB recommended"),
    ),
    h("section", { class: "panel" }, h("h2", {}, "Signatures by severity"),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, IPS_SEVERITIES.map((s) => h("th", {}, s[0].toUpperCase() + s.slice(1))), h("th", {}, "Disabled"))),
        h("tbody", {}, h("tr", {}, IPS_SEVERITIES.map((s) => h("td", { class: "mono" }, String(counts[s] || 0))), h("td", { class: "mono" }, String(sig.disabled || 0))))))),
    h("section", { class: "panel" }, h("h2", {}, "Inspected rules"),
      (st.rules || []).length ? chips(st.rules)
        : h("p", { class: "muted" }, "No rule uses an IPS profile yet. Pick one on an allow rule (Policy → IPS profile), or in the CLI: set rule NAME ips-profile default."),
      h("p", { class: "muted small" }, "Matches show in Logs → Threats. Test from a client behind the firewall: a request containing SJB-IPS-TEST-CRITICAL (or MAJOR, MINOR, INFO) matches SJB-OS's test signatures.")));
}

async function pageSystem() {
  let up = null;
  if (can("upgrades")) { try { up = await api("GET", "upgrade"); } catch (e) { up = { error: e.message }; } }
  const file = h("input", { type: "file", accept: ".upgrade" });
  const status = h("div", { class: "muted" });
  const install = h("button", { class: "primary hidden" }, "Install");
  const upload = h("button", { onclick: async () => {
    if (!file.files[0]) return toast("Choose a .upgrade file first.");
    status.textContent = "Uploading and checking the signature…";
    install.classList.add("hidden");
    try {
      const r = await api("POST", "upgrade", undefined, file.files[0]);
      status.textContent = `Signature OK: SJB-OS ${r.version} (${r.files} files). Installing restarts ngfwd; the firewall keeps its rules meanwhile.`;
      install.classList.remove("hidden");
    } catch (e) { status.textContent = e.message; }
  } }, "Upload and check");
  install.addEventListener("click", async () => {
    try {
      await api("POST", "upgrade/start", {});
      install.classList.add("hidden");
      status.textContent = "Installing… this page reconnects when ngfwd is back.";
      waitForUpgrade(up.version);
    } catch (e) { status.textContent = e.message; }
  });

  const history = (up && up.history) || [];
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Administration")),
    !up ? null : h("section", { class: "panel" }, h("h2", {}, "Upgrade"),
      up.error ? h("p", { class: "error" }, up.error) : h("div", {},
        h("p", {}, `Installed: SJB-OS ${up.version}.`, up.in_progress ? h("strong", {}, " An upgrade is in progress.") : null),
        h("p", { class: "muted small" }, "Upgrades are signed bundles (.upgrade files from the GitHub release). Config, tags and revisions are kept. If ngfwd does not come back healthy, the previous version is restored automatically."),
        can("upgrades", "change") ? [h("div", { class: "row" }, h("label", {}, "Bundle", file), upload, install), status] : h("p", { class: "muted small" }, "Your role can see upgrades but not install them."),
        up.rollback_to && can("upgrades", "change") ? h("p", {}, h("button", { onclick: () => confirmDialog(`Roll back to SJB-OS ${up.rollback_to}?`, "The files the last upgrade replaced are restored and ngfwd restarts.", async () => {
          await api("POST", "upgrade/rollback", {}); toast("Rolling back…"); waitForUpgrade(up.version);
        }, "Roll back") }, `Roll back to ${up.rollback_to}`)) : null,
        history.length ? h("div", { class: "table-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, h("th", {}, "When"), h("th", {}, "Action"), h("th", {}, "From → to"), h("th", {}, "Result"))),
          h("tbody", {}, history.slice().reverse().map((e) => h("tr", {}, h("td", {}, new Date(e.time).toLocaleString()), h("td", {}, e.action),
            h("td", {}, `${e.from} → ${e.to}`), h("td", {}, h("span", { class: e.result === "ok" ? "action-allow" : e.result === "in-progress" ? "" : "action-deny" }, e.result), e.error ? h("div", { class: "muted small" }, e.error) : null)))))) : null)),
    h("section", { class: "panel" }, h("h2", {}, "Your account"),
      h("p", {}, "Your password and SSH keys are on ", h("a", { href: "#account" }, "My account"), ".",
        isSuper() ? [" Other users and roles: ", h("a", { href: "#users" }, "Users"), " and ", h("a", { href: "#roles" }, "Roles"), "."] : null)),
    !state.me.config_view ? null :     h("section", { class: "panel" }, h("h2", {}, "Candidate config as YAML"),
      h("p", { class: "muted small" }, "What fwctl show prints. Saving from this UI rewrites the file, so YAML comments are not kept."),
      h("button", { onclick: async () => {
        const res = await fetch("/ui/api/config/candidate?format=yaml", { credentials: "same-origin" });
        modal("Candidate config", h("pre", { class: "block" }, await res.text()), { submit: null, wide: true });
      } }, "Show YAML")),
  );
}

function waitForUpgrade(from) {
  let n = 0;
  const poll = async () => {
    n++;
    try {
      const st = await api("GET", "upgrade");
      const last = st.history[st.history.length - 1];
      if (!st.in_progress && last && last.result !== "in-progress") {
        toast(last.result === "ok" ? `SJB-OS ${st.version} is running. Fresh paint on the gatehouse, same guard.` : `Upgrade ${last.result}: ${last.error || ""}`);
        await refresh(); route();
        return;
      }
    } catch (e) {
      if (e.status === 401) return; // ngfwd restarted: sessions are gone, log in again
    }
    if (n < 120) setTimeout(poll, 2000);
  };
  setTimeout(poll, 2000);
}

// ---- users, roles and your own account --------------------------------------
const fmtWhen = (t) => (t ? new Date(t).toLocaleString() : "never");
const pwField = (label, auto = "new-password") => {
  const input = h("input", { type: "password", autocomplete: auto, minlength: auto === "new-password" ? 10 : null });
  return { node: h("label", {}, label, input), get: () => input.value, input };
};
function userStatus(u) {
  const s = u.disabled ? h("span", { class: "action-deny" }, "disabled")
    : u.locked ? h("span", { class: "action-reset" }, `locked until ${new Date(u.locked_until).toLocaleTimeString()}`)
    : h("span", { class: "action-allow" }, "active");
  return [s, !u.password_set ? h("span", { class: "muted small" }, " no password") : null, u.permanent ? [" ", h("span", { class: "chip" }, "permanent")] : null];
}

// A user's SSH keys, with add and delete. onChange redraws.
function keysPanel(u, onChange) {
  const add = () => {
    const key = textArea("Public key", "", { placeholder: "ssh-ed25519 AAAA... you@laptop", rows: 3 });
    modal(`Add an SSH key for ${u.name}`, h("div", {},
      h("p", { class: "muted small" }, "One line from the .pub file (for example ~/.ssh/id_ed25519.pub). It works for SSH logins straight away."), key.node),
    { submit: "Add", wide: true, onSubmit: async () => {
      const k = await api("POST", `users/${encodeURIComponent(u.name)}/ssh-keys`, { key: key.get() });
      toast(`Key ${k.fingerprint.slice(0, 20)}… added.`); onChange();
    } });
  };
  const del = (k) => confirmDialog(`Delete this key of ${u.name}?`, `${k.type} ${k.fingerprint} ${k.comment || ""}: SSH logins with it stop working.`, async () => {
    await api("DELETE", `users/${encodeURIComponent(u.name)}/ssh-keys/${encodeURIComponent(k.fingerprint)}`);
    toast("Key deleted."); onChange();
  }, "Delete");
  return h("section", { class: "panel" },
    h("div", { class: "page-head" }, h("h2", {}, "SSH keys"), h("span", { class: "spacer" }), h("button", { class: "primary", onclick: add }, "Add key")),
    u.ssh_keys.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Type", "Fingerprint", "Comment", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, u.ssh_keys.map((k) => h("tr", {}, h("td", {}, k.type), h("td", { class: "mono small" }, k.fingerprint), h("td", {}, k.comment || ""),
        h("td", { class: "actions" }, h("button", { class: "link danger", onclick: () => del(k) }, "Delete")))))))
      : h("p", { class: "empty" }, "No SSH keys: password logins only."));
}

function permsTable(perms, superuser) {
  const areas = (state.me && state.me.areas) || [];
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "Area"), h("th", {}, "Access"), h("th", {}, "Covers"))),
    h("tbody", {}, areas.map((a) => {
      const l = superuser ? (a.view_only ? "view" : "change") : (perms || {})[a.area] || "";
      return h("tr", {}, h("td", {}, a.title), h("td", {}, l ? h("span", { class: l === "change" ? "action-allow" : "" }, l) : h("span", { class: "muted" }, "none")), h("td", { class: "muted small" }, a.covers));
    }))));
}

async function pageAccount() {
  const u = await api("GET", "me");
  const m = state.me;
  const cur = pwField("Current password", "current-password"), nw = pwField("New password (10+ characters)"), again = pwField("Again");
  const change = h("button", { class: "primary", onclick: async () => {
    if (nw.get() !== again.get()) return toast("The new passwords don't match.");
    try {
      await api("POST", "password", { current: cur.get(), new: nw.get() });
      cur.input.value = nw.input.value = again.input.value = "";
      toast("Password changed for the web UI, SSH and the console. Your other sessions were logged out.");
    } catch (e) { toast(e.message); }
  } }, "Change password");
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "My account")),
    h("div", { class: "cards" },
      card("User", u.name, u.permanent ? "permanent superuser" : ""),
      card("Role", m.role, m.superuser ? "everything, including users and roles" : ""),
      card("Last web login", fmtWhen(u.last_login)),
    ),
    h("section", { class: "panel" }, h("h2", {}, "Password"),
      h("p", { class: "muted small" }, "One password for the web UI, SSH and the VMware console. Changing it here changes all three, as does passwd in the CLI. Five wrong passwords in a row lock the account for 15 minutes."),
      h("div", { class: "row" }, cur.node, nw.node, again.node, change)),
    keysPanel(u, route),
    h("section", { class: "panel" }, h("h2", {}, "What your role allows"), permsTable(m.permissions, m.superuser)));
}

async function pageUsers() {
  const [users, roles] = await Promise.all([api("GET", "users"), api("GET", "roles")]);
  const roleOpts = roles.map((r) => ({ value: r.name, label: r.builtin ? r.name : `${r.name} (custom)` }));
  const add = () => {
    const name = textField("User name", "", { required: true, placeholder: "alice", hint: "Lower-case letters, digits, - or _" });
    const role = selectField("Role", "read-only", roleOpts);
    const p1 = pwField("Password (10+ characters)"), p2 = pwField("Again");
    modal("Add a user", h("div", {}, h("div", { class: "grid2" }, name.node, role.node, p1.node, p2.node),
      h("p", { class: "muted small" }, "The user logs in to the web UI, SSH and the VMware console with this one password, and lands in the CLI, never a shell.")),
    { submit: "Add", onSubmit: async () => {
      if (p1.get() !== p2.get()) throw new Error("The passwords don't match.");
      await api("POST", "users", { name: name.get(), role: role.get(), password: p1.get() });
      toast(`User ${name.get()} added.`); route();
    } });
  };
  const edit = (u) => {
    const role = selectField("Role", u.role, roleOpts, { hint: u.permanent ? "admin is always a superuser" : "" });
    const dis = checkField("Disabled: no logins, and open sessions end", u.disabled);
    if (u.permanent || u.name === state.user) { role.node.querySelector("select").disabled = true; dis.node.querySelector("input").disabled = true; }
    modal(`Edit ${u.name}`, h("div", {}, role.node, dis.node), { onSubmit: async () => {
      const body = {};
      if (role.get() !== u.role) body.role = role.get();
      if (dis.get() !== u.disabled) body.disabled = dis.get();
      if (Object.keys(body).length) await api("PATCH", `users/${encodeURIComponent(u.name)}`, body);
      toast(`${u.name} saved.`); route();
    } });
  };
  const setPw = (u) => {
    const p1 = pwField("New password (10+ characters)"), p2 = pwField("Again");
    modal(`Set the password of ${u.name}`, h("div", {}, h("p", { class: "muted small" }, "For the web UI, SSH and the console. Their open sessions end."), h("div", { class: "grid2" }, p1.node, p2.node)),
      { submit: "Set password", onSubmit: async () => {
        if (p1.get() !== p2.get()) throw new Error("The passwords don't match.");
        await api("POST", `users/${encodeURIComponent(u.name)}/password`, { password: p1.get() });
        toast(`Password of ${u.name} set.`); route();
      } });
  };
  const keys = (u) => {
    const body = h("div");
    const draw = async () => {
      const fresh = (await api("GET", "users")).find((x) => x.name === u.name);
      body.replaceChildren(keysPanel(fresh, draw));
    };
    body.append(keysPanel(u, draw));
    modal(`SSH keys of ${u.name}`, body, { submit: null, wide: true });
  };
  const unlock = async (u) => { await api("POST", `users/${encodeURIComponent(u.name)}/unlock`, {}); toast(`${u.name} unlocked.`); route(); };
  const del = (u) => confirmDialog(`Delete user ${u.name}?`, "Their login, SSH keys and sessions go. Revisions they committed keep their name.", async () => {
    await api("DELETE", `users/${encodeURIComponent(u.name)}`); toast(`User ${u.name} deleted.`); route();
  }, "Delete");
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Users"), h("span", { class: "spacer" }), h("button", { class: "primary", onclick: add }, "Add user")),
    h("p", { class: "tagline" }, "Everyone through the gate signs the book."),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["User", "Role", "Status", "Last web login", "SSH keys", "Changed", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, users.map((u) => h("tr", {},
        h("td", {}, h("strong", {}, u.name), u.name === state.user ? h("span", { class: "muted small" }, " (you)") : null),
        h("td", {}, u.role), h("td", {}, userStatus(u)), h("td", {}, fmtWhen(u.last_login)), h("td", { class: "num" }, u.ssh_keys.length),
        h("td", { class: "muted small" }, u.changed ? `${new Date(u.changed).toLocaleDateString()} by ${u.changed_by}` : ""),
        h("td", { class: "actions" },
          h("button", { class: "link", onclick: () => edit(u) }, "Edit"),
          h("button", { class: "link", onclick: () => setPw(u) }, "Password"),
          h("button", { class: "link", onclick: () => keys(u) }, "Keys"),
          u.locked ? h("button", { class: "link", onclick: () => unlock(u) }, "Unlock") : null,
          u.permanent || u.name === state.user ? null : h("button", { class: "link danger", onclick: () => del(u) }, "Delete"))))))),
    h("p", { class: "muted small" }, "Roles decide what each user may see and change: ", h("a", { href: "#roles" }, "Roles"), ". admin is permanent: it can't be deleted, disabled or given another role."));
}

async function pageRoles() {
  const roles = await api("GET", "roles");
  const areas = state.me.areas || [];
  const editor = (r) => {
    const isNew = !r;
    r = r || { name: "", description: "", permissions: {} };
    const name = textField("Name", r.name, { required: true, placeholder: "policy-editor" });
    if (!isNew) name.node.querySelector("input").disabled = true;
    const desc = textField("Description", r.description, { placeholder: "What the role is for" });
    const picks = {};
    const grid = h("table", {}, h("thead", {}, h("tr", {}, ["Area", "None", "View", "Change", "Covers"].map((t) => h("th", {}, t)))),
      h("tbody", {}, areas.map((a) => {
        const cur = (r.permissions || {})[a.area] || "";
        const radio = (v) => {
          const el = h("input", { type: "radio", name: "perm-" + a.area, value: v, checked: cur === v, disabled: v === "change" && a.view_only, "aria-label": `${a.title}: ${v || "none"}` });
          el.addEventListener("change", () => { picks[a.area] = v; });
          return h("td", {}, el);
        };
        picks[a.area] = cur;
        return h("tr", {}, h("td", {}, a.title), radio(""), radio("view"), radio("change"), h("td", { class: "muted small" }, a.covers));
      })));
    modal(isNew ? "New role" : `Edit role ${r.name}`, h("div", {}, h("div", { class: "grid2" }, name.node, desc.node),
      h("div", { class: "table-wrap" }, grid),
      h("p", { class: "muted small" }, "Config areas are checked on every edit and commit: a commit that touches an area the role can't change is refused. Users and roles are for superusers only.")),
    { wide: true, onSubmit: async () => {
      const perms = {};
      for (const [k, v] of Object.entries(picks)) if (v) perms[k] = v;
      await api("PUT", `roles/${encodeURIComponent(name.get())}`, { description: desc.get(), permissions: perms });
      toast(`Role ${name.get()} saved. Users who have it get it on their next click.`); route();
    } });
  };
  const view = (r) => modal(`Role ${r.name}`, h("div", {}, h("p", {}, r.description), permsTable(r.permissions, r.superuser)), { submit: null, wide: true });
  const del = (r) => confirmDialog(`Delete role ${r.name}?`, "Only roles nobody has can be deleted.", async () => {
    await api("DELETE", `roles/${encodeURIComponent(r.name)}`); toast(`Role ${r.name} deleted.`); route();
  }, "Delete");
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Roles"), h("span", { class: "spacer" }), h("button", { class: "primary", onclick: () => editor(null) }, "Add role")),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Role", "Kind", "Users", "Description", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, roles.map((r) => h("tr", {},
        h("td", {}, h("strong", {}, r.name)), h("td", {}, r.builtin ? "built-in" : "custom"),
        h("td", {}, r.users.length ? chips(r.users) : h("span", { class: "muted" }, "nobody")), h("td", {}, r.description),
        h("td", { class: "actions" }, h("button", { class: "link", onclick: () => view(r) }, "View"),
          r.builtin ? null : [h("button", { class: "link", onclick: () => editor(r) }, "Edit"), h("button", { class: "link danger", onclick: () => del(r) }, "Delete")])))))),
    h("p", { class: "muted small" }, "Built-in roles: superuser (everything, including users, roles, upgrades and the decryption CA), admin (config, commits, rollbacks, tags, IPS updates) and read-only (sees everything except secrets)."));
}

// ---- router ----------------------------------------------------------------
const pages = {
  dashboard: pageDashboard, policy: pagePolicy, nat: pageNat, objects: pageObjects,
  network: pageNetwork, routing: pageRouting, dhcp: pageDHCP, apps: pageApps, ips: pageIPS, decryption: pageDecryption, tags: pageTags, revisions: pageRevisions, logs: pageLogs, system: pageSystem,
  account: pageAccount, users: pageUsers, roles: pageRoles,
};

async function route() {
  if (!state.status) return;
  clearInterval(state.logTimer);
  clearInterval(state.dashTimer);
  const name = location.hash.slice(1) || "dashboard";
  let page = pages[name] || pageDashboard;
  if (pageNeeds[name] && !pageNeeds[name]()) {
    page = () => h("div", { class: "panel" }, h("h1", {}, "Not for your role"),
      h("p", {}, `Role ${state.me.role} can't see this page. Ask a superuser if you need it.`));
  }
  for (const a of document.querySelectorAll("#nav a")) a.classList.toggle("active", a.getAttribute("href") === "#" + name);
  for (const m of document.querySelectorAll("#nav .menu")) m.querySelector(".menu-btn").classList.toggle("active", !!m.querySelector("a.active"));
  try {
    const node = await page();
    $("#main").replaceChildren(node);
  } catch (e) {
    if (e.status !== 401) $("#main").replaceChildren(h("div", { class: "panel" }, errorBox(e)));
  }
  const titles = { dhcp: "DHCP", apps: "Applications", ips: "IPS", decryption: "Decryption", network: "Interfaces", system: "Administration", account: "My account" };
  document.title = `SJB-OS · ${titles[name] || name[0].toUpperCase() + name.slice(1)}`;
}

window.addEventListener("hashchange", () => { closeMenus(); route(); });

// Grouped navigation: each section button opens its items. Click or Enter
// toggles it, a click elsewhere or Escape closes it, arrow keys move
// through the items.
function closeMenus(except) {
  for (const b of document.querySelectorAll("#nav .menu-btn")) {
    if (b === except) continue;
    b.setAttribute("aria-expanded", "false");
    document.getElementById(b.getAttribute("aria-controls")).classList.add("hidden");
  }
}
for (const b of document.querySelectorAll("#nav .menu-btn")) {
  const list = document.getElementById(b.getAttribute("aria-controls"));
  const items = () => [...list.querySelectorAll("a")];
  const open = (focus) => {
    closeMenus(b);
    b.setAttribute("aria-expanded", "true");
    list.classList.remove("hidden");
    if (focus) (list.querySelector("a.active") || items()[0]).focus();
  };
  b.addEventListener("click", () => (b.getAttribute("aria-expanded") === "true" ? closeMenus() : open(false)));
  list.addEventListener("click", (e) => { if (e.target.closest("a")) closeMenus(); });
  b.addEventListener("keydown", (e) => { if (e.key === "ArrowDown") { e.preventDefault(); open(true); } });
  list.addEventListener("keydown", (e) => {
    const all = items(), i = all.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); all[(i + 1) % all.length].focus(); }
    if (e.key === "ArrowUp") { e.preventDefault(); all[(i - 1 + all.length) % all.length].focus(); }
    if (e.key === "Escape") { closeMenus(); b.focus(); }
  });
}
document.addEventListener("click", (e) => { if (!e.target.closest("#nav .menu")) closeMenus(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeMenus(); });

// Keep the bars and dashboard fresh (pending commit timers, tag counts).
setInterval(async () => {
  if ($("#app").classList.contains("hidden") || $("#dialog").open) return;
  try {
    const before = JSON.stringify(state.status);
    await refresh();
    if ((location.hash || "#dashboard") === "#dashboard" && before !== JSON.stringify(state.status)) route();
  } catch {}
}, 15000);

(async () => {
  try { await enter(await api("GET", "session")); } catch { showLogin(); }
})();

