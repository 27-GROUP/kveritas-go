"use strict";

const COL = 18;
const DOT_Y = 19;
const SVGNS = "http://www.w3.org/2000/svg";
const KIND = {
  run: "run", failed: "failed", checkpoint: "checkpoint", restore: "restore",
  branch: "branch", switch: "switch", "set-aside": "set aside", "bring-back": "bring back",
};

let token = "";
let state = null;
let lastText = "";
const open = new Set();

function $(id) { return document.getElementById(id); }

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "style") n.style.cssText = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) {
    if (k !== null && k !== undefined && k !== false) n.append(k instanceof Node ? k : String(k));
  }
  return n;
}

// Inline style attributes are blocked by the page's CSP; styles go through the DOM.
function svg(tag, attrs) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "style") n.style.cssText = v;
    else n.setAttribute(k, v);
  }
  return n;
}

function readToken() {
  const h = location.hash.slice(1);
  if (h) {
    try { sessionStorage.setItem("kv-token", h); } catch (e) {}
    history.replaceState(null, "", location.pathname);
    return h;
  }
  try { return sessionStorage.getItem("kv-token") || ""; } catch (e) { return ""; }
}

async function call(path, body) {
  const opts = { headers: { "X-KV-Token": token } };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

let toastTimer = 0;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 5000);
}

async function act(path, body) {
  try {
    const out = await call(path, body);
    toast((out.messages || []).join("\n") || "Done");
  } catch (e) {
    toast(e.message);
  }
  await refresh(true);
}

function ago(iso) {
  const t = Date.parse(iso);
  if (!t || t < 0) return "";
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  return new Date(t).toLocaleDateString();
}

function fmt(v) {
  if (Math.abs(v) >= 1e5 || (v !== 0 && Math.abs(v) < 1e-3)) return v.toExponential(3);
  return String(+v.toPrecision(5));
}

// Modal with an optional text field; resolves to the text, or null when cancelled.
function ask(title, text, okLabel, placeholder) {
  return new Promise((resolve) => {
    $("mtitle").textContent = title;
    $("mtext").textContent = text;
    const input = $("minput");
    input.hidden = placeholder === undefined;
    input.value = "";
    input.placeholder = placeholder || "";
    $("mok").textContent = okLabel;
    $("modal").hidden = false;
    (input.hidden ? $("mok") : input).focus();
    const done = (v) => {
      $("modal").hidden = true;
      $("mok").onclick = $("mcancel").onclick = input.onkeydown = null;
      resolve(v);
    };
    $("mok").onclick = () => done(input.value);
    $("mcancel").onclick = () => done(null);
    input.onkeydown = (e) => { if (e.key === "Enter") done(input.value); if (e.key === "Escape") done(null); };
  });
}

async function restore(n) {
  const label = n.title ? `${n.id} "${n.title}"` : n.id;
  const ok = await ask("Restore checkpoint " + label + "?",
    "Files that changed since this checkpoint are put back. New files are left alone. If you have unsaved changes, they are kept in a new checkpoint first. The restore is added to your history.",
    "Restore");
  if (ok !== null) act("/api/restore", { id: n.id });
}

async function setAside(n, undo) {
  if (undo) {
    act("/api/set-aside", { run: n.id, undo: true });
    return;
  }
  const why = await ask("Set run " + n.id + " aside?",
    "It leaves the main results but stays in the report, signed and counted, with your reason.",
    "Set aside", "Reason, e.g. wrong config");
  if (why !== null) act("/api/set-aside", { run: n.id, reason: why });
}

function actionsFor(n) {
  if (state.busy) return [];
  if (n.kind === "checkpoint") return [["Restore", () => restore(n)]];
  if (n.kind === "run") return n.aside ? [["Bring back", () => setAside(n, true)]] : [["Set aside", () => setAside(n, false)]];
  return [];
}

function closeMenu() { $("menu").hidden = true; }

function showMenu(e, n) {
  e.preventDefault();
  const m = $("menu");
  m.replaceChildren();
  const items = actionsFor(n);
  if (n.id && !n.id.startsWith("#")) {
    items.push(["Copy ID", () => navigator.clipboard && navigator.clipboard.writeText(n.id).then(() => toast("Copied " + n.id))]);
  }
  if (!items.length) return;
  for (const [label, fn] of items) {
    m.append(el("button", { type: "button", onclick: () => { closeMenu(); fn(); } }, label));
  }
  m.hidden = false;
  m.style.left = Math.min(e.clientX, innerWidth - 190) + "px";
  m.style.top = Math.min(e.clientY, innerHeight - m.offsetHeight - 10) + "px";
}

function glyph(g, n, x) {
  const y = DOT_Y;
  if (n.glyph === "x") {
    g.append(svg("path", { d: `M${x - 4} ${y - 4}L${x + 4} ${y + 4}M${x + 4} ${y - 4}L${x - 4} ${y + 4}`, stroke: "currentColor", "stroke-width": 2 }));
  } else if (n.glyph === "@") {
    g.append(svg("circle", { cx: x, cy: y, r: 6, fill: "var(--strong)", stroke: "var(--strong)" }));
  } else if (n.kind === "checkpoint") {
    g.append(svg("rect", { x: x - 5, y: y - 5, width: 10, height: 10, fill: "var(--bg)", stroke: "currentColor", "stroke-width": 1.6 }));
  } else if (n.kind === "run") {
    g.append(svg("circle", { cx: x, cy: y, r: 5, fill: "var(--bg)", stroke: "currentColor", "stroke-width": 1.6, "stroke-dasharray": n.aside ? "2 2" : "none" }));
  } else {
    g.append(svg("circle", { cx: x, cy: y, r: 3, fill: "currentColor" }));
  }
}

function gutter(lanes, n) {
  const box = el("div", { class: "gutter", style: `width:${lanes.length * COL + 6}px;color:var(--muted)` });
  const s = svg("svg", {});
  lanes.forEach((l, c) => {
    const x = c * COL + COL / 2 + 2;
    if (l.node) {
      if (l.up) s.append(svg("line", { x1: x, y1: 0, x2: x, y2: DOT_Y, stroke: "currentColor", "stroke-width": 1.6 }));
      if (l.down) s.append(svg("line", { x1: x, y1: DOT_Y, x2: x, y2: "100%", stroke: "currentColor", "stroke-width": 1.6 }));
      glyph(s, n, x);
    } else if (l.up && l.down) {
      s.append(svg("line", { x1: x, y1: 0, x2: x, y2: "100%", stroke: "currentColor", "stroke-width": 1.6 }));
    }
  });
  box.append(s);
  return box;
}

function linkRow(r) {
  const w = r.lanes.length * COL + 6;
  const s = svg("svg", { width: w, height: 16, style: "color:var(--muted)" });
  r.lanes.forEach((l, c) => {
    const x = c * COL + COL / 2 + 2;
    if (c === r.from || (l.down && c !== r.to)) {
      s.append(svg("line", { x1: x, y1: 0, x2: x, y2: 16, stroke: "currentColor", "stroke-width": 1.6 }));
    }
  });
  const px = r.from * COL + COL / 2 + 2;
  const cx = r.to * COL + COL / 2 + 2;
  s.append(svg("path", { d: `M${cx} 0 C${cx} 12, ${px} 6, ${px} 16`, fill: "none", stroke: "currentColor", "stroke-width": 1.6 }));
  return el("div", { class: "link" }, s);
}

function detailOf(n) {
  const d = el("div", { class: "detail", onclick: (e) => e.stopPropagation() });
  if (n.results && n.results.length) {
    d.append(el("table", {},
      el("tr", {}, el("th", {}, "Result"), el("th", {}, "Final value"), el("th", {}, "Step"), el("th", {}, "Source")),
      n.results.map((v) => el("tr", {}, el("td", {}, v.name), el("td", { class: "mono" }, fmt(v.value)), el("td", {}, v.step || ""), el("td", {}, v.source)))));
  }
  if (n.measured && n.measured.length) {
    d.append(el("table", {},
      el("tr", {}, el("th", {}, "Measured"), el("th", {}, "Value")),
      n.measured.map((v) => el("tr", {}, el("td", {}, v.name), el("td", { class: "mono" }, fmt(v.value))))));
  }
  if (n.changed && n.changed.length) {
    d.append(el("ul", { class: "files" }, n.changed.map((c) => {
      const i = c.indexOf(" ");
      return el("li", {}, el("span", { class: "op" }, c.slice(0, i)), c.slice(i + 1));
    })));
  }
  if (n.at) d.append(el("div", { class: "muted small" }, new Date(n.at).toLocaleString()));
  return d;
}

function nodeRow(r) {
  const n = state.nodes[r.node];
  const key = n.kind + ":" + n.inv;
  const acts = actionsFor(n);
  let title = n.title || "";
  if (n.kind === "checkpoint") title = title ? `"${title}"` : "(no message)";
  if (n.kind === "failed") title = title ? `${title}  ${n.note}` : n.note;
  if (n.kind === "set-aside" && n.note) title += ": " + n.note;

  const chips = [];
  if (n.aside) chips.push(el("span", { class: "chip tag" }, "set aside" + (n.note ? ": " + n.note : "")));
  if (n.branch !== "main") chips.push(el("span", { class: "chip" }, n.branch));
  for (const v of (n.results || []).slice(0, 6)) chips.push(el("span", { class: "chip mono" }, `${v.name} ${fmt(v.value)}`));

  const row = el("div", {
    class: "node",
    onclick: () => { if (open.has(key)) open.delete(key); else open.add(key); render(); },
    oncontextmenu: (e) => showMenu(e, n),
  },
  gutter(r.lanes, n),
  el("div", { class: "body" },
    el("div", { class: "head" },
      el("span", { class: "kind" }, n.glyph === "@" ? "you are here" : KIND[n.kind] || n.kind),
      el("span", { class: n.kind === "run" || n.kind === "failed" ? "title mono" : "title" }, title),
      el("span", { class: "meta" },
        el("span", { class: "actions" }, acts.map(([label, fn]) =>
          el("button", { class: "btn small ghost", type: "button", onclick: (e) => { e.stopPropagation(); fn(); } }, label))),
        n.duration ? el("span", {}, n.duration) : null,
        el("span", { title: n.at ? new Date(n.at).toLocaleString() : "" }, n.at ? ago(n.at) : ""),
        el("span", { class: "id" }, n.id))),
    chips.length ? el("div", { class: "chips" }, chips) : null,
    open.has(key) ? detailOf(n) : null));

  if (n.glyph === "@" && !state.busy) {
    row.draggable = true;
    row.addEventListener("dragstart", (e) => { e.dataTransfer.setData("text/plain", "kv-here"); });
  }
  if (n.kind === "checkpoint" && !state.busy) {
    row.addEventListener("dragover", (e) => { e.preventDefault(); row.classList.add("drop"); });
    row.addEventListener("dragleave", () => row.classList.remove("drop"));
    row.addEventListener("drop", (e) => {
      e.preventDefault();
      row.classList.remove("drop");
      if (e.dataTransfer.getData("text/plain") === "kv-here") restore(n);
    });
  }
  return row;
}

function renderWorking() {
  const s = state;
  $("where").textContent = `session ${s.session.slice(0, 8)} · ${s.disclosure} · ${s.online ? "server" : "local signing"}` +
    (s.queued ? ` · ${s.queued} step(s) waiting to reach the server` : "");

  const sel = $("branch");
  sel.replaceChildren(...s.branches.map((b) => el("option", { value: b, selected: b === s.branch }, b)),
    el("option", { value: "+" }, "New branch…"));
  sel.disabled = !!s.busy;

  const based = $("based");
  const pill = $("filestate");
  const list = $("files");
  list.replaceChildren();
  if (!s.checkpoint) {
    based.textContent = "No checkpoint yet. Save one to be able to come back to this point.";
    based.className = "based muted";
    pill.hidden = true;
  } else {
    based.className = "based";
    based.replaceChildren("Based on checkpoint ", el("span", { class: "mono" }, s.checkpoint.id),
      s.checkpoint.message ? ` "${s.checkpoint.message}"` : "");
    pill.hidden = false;
    pill.textContent = s.clean ? "CLEAN" : "CHANGED";
    pill.className = s.clean ? "pill" : "pill changed";
    const f = s.files || {};
    for (const [op, names] of [["modified", f.modified], ["added", f.added], ["deleted", f.deleted]]) {
      for (const name of names || []) list.append(el("li", {}, el("span", { class: "op" }, op), name));
    }
  }
  for (const id of ["cpmsg", "cpfiles"]) $(id).disabled = !!s.busy;
  $("cpform").querySelector("button").disabled = !!s.busy;

  const notice = $("notice");
  notice.hidden = !s.busy;
  notice.textContent = s.busy || "";
}

function render() {
  if (!state) return;
  if (state.gone) {
    $("working").hidden = true;
    $("tree").replaceChildren(el("p", { class: "muted" }, "This session was sealed or removed. Start a new one with kveritas run or kveritas shell."));
    return;
  }
  renderWorking();
  const tree = $("tree");
  if (!state.rows || !state.rows.length) {
    tree.replaceChildren(el("p", { class: "muted" }, "Nothing recorded yet. Run a command with kveritas run, or open kveritas shell."));
    return;
  }
  tree.replaceChildren(...state.rows.map((r) => (r.node < 0 ? linkRow(r) : nodeRow(r))));
}

async function refresh(force) {
  if (!token) {
    $("notice").hidden = false;
    $("notice").textContent = "Open the link printed in your terminal; it carries the key for this page.";
    return;
  }
  try {
    const s = await call("/api/state");
    const text = JSON.stringify(s);
    if (force || text !== lastText) {
      lastText = text;
      state = s;
      render();
    }
  } catch (e) {
    $("notice").hidden = false;
    $("notice").textContent = "Cannot reach kveritas web: " + e.message + ". Is it still running in your terminal?";
  }
}

function setTheme(t) {
  document.documentElement.dataset.theme = t;
  $("theme").textContent = t === "dark" ? "Light" : "Dark";
  try { localStorage.setItem("kv-theme", t); } catch (e) {}
}

$("theme").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));

$("branch").addEventListener("change", async (e) => {
  let name = e.target.value;
  if (name === "+") {
    name = await ask("New branch", "Runs after this go on the new branch. Your files do not change.", "Start branch", "e.g. quick-test");
    if (!name) { render(); return; }
  }
  if (name !== state.branch) act("/api/branch", { name });
});

$("cpform").addEventListener("submit", (e) => {
  e.preventDefault();
  const files = $("cpfiles").value.split(",").map((f) => f.trim()).filter(Boolean);
  act("/api/checkpoint", { message: $("cpmsg").value, files }).then(() => { $("cpmsg").value = ""; $("cpfiles").value = ""; });
});

document.addEventListener("click", closeMenu);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeMenu(); });

try { setTheme(localStorage.getItem("kv-theme") || "dark"); } catch (e) { setTheme("dark"); }
token = readToken();
refresh(true);
setInterval(() => { if (!document.hidden) refresh(false); }, 3000);
setInterval(() => { if (state && !document.hidden) render(); }, 60000);
