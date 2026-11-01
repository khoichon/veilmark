// Veilmark web app: UI, key management and job handling (main thread).
// All media and key processing happens in worker.js (Python via Pyodide).

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const STORE_KEY = "veilmark.keyfile.v1";

// ------------------------------------------------------------------ worker
let worker = null;
let ready = false;
let nextId = 1;
const pending = new Map();
// Encrypted copy of the current keys (random passphrase, memory only) so keys survive
// a worker restart after "Cancel".
let session = null; // {text, pass}
let unsaved = false;

function startWorker() {
  ready = false;
  setBoot(0, "Starting…");
  $("engine").classList.remove("done");
  worker = new Worker("worker.js", { type: "module" });
  worker.onmessage = (ev) => {
    const m = ev.data;
    if (m.type === "boot") setBoot(m.f, m.msg);
    else if (m.type === "ready") onReady(m.info);
    else if (m.type === "fatal") setBoot(0, "Could not start: " + m.message);
    else if (m.type === "progress") pending.get(m.id)?.onProgress?.(m.f, m.msg);
    else if (m.type === "result" || m.type === "error") {
      const p = pending.get(m.id);
      pending.delete(m.id);
      if (!p) return;
      m.type === "result" ? p.resolve(m.value) : p.reject(new Error(m.message));
    }
  };
  worker.onerror = (e) => setBoot(0, "Engine error: " + (e.message || "failed to load"));
}

function call(op, args = {}, onProgress = null, transfer = []) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject, onProgress });
    worker.postMessage({ id, op, args }, transfer);
  });
}

async function restartWorker() {
  worker.terminate();
  for (const p of pending.values()) p.reject(new Error("cancelled"));
  pending.clear();
  startWorker();
  if (session) {
    try {
      render(await call("load_keyfile", { text: session.text, passphrase: session.pass }));
    } catch (e) {
      render(await call("status"));
    }
  }
}

function setBoot(f, msg) {
  $("boot-fill").style.width = `${Math.round(f * 100)}%`;
  $("boot-msg").textContent = msg;
}

async function onReady(info) {
  ready = true;
  $("engine").classList.add("done");
  $("boot-msg").textContent = "Engine ready · processing stays on this device";
  $("about").textContent = `Veilmark ${info.version} · Python runtime: Pyodide ${info.pyodide}`;
  for (const id of ["btn-generate", "btn-open"]) $(id).disabled = false;
  showRemembered();
  render(await call("status"));
}

// --------------------------------------------------------------- dialogs
function askName() {
  const d = $("name-dialog");
  $("name-input").value = "";
  d.showModal();
  return new Promise((res) => d.addEventListener("close", () => res(d.returnValue === "ok" ? $("name-input").value.trim() : null), { once: true }));
}

function askPassphrase({ title, text, confirm, remember }) {
  const d = $("pw-dialog");
  $("pw-title").textContent = title;
  $("pw-text").textContent = text;
  $("pw-1").value = $("pw-2").value = "";
  $("pw-confirm-row").hidden = !confirm;
  $("pw-remember-row").hidden = !remember;
  $("pw-remember").checked = false;
  $("pw-err").textContent = "";
  d.showModal();
  return new Promise((res) => {
    const form = $("pw-form");
    const onSubmit = (ev) => {
      if (ev.submitter?.value !== "ok") return;
      const a = $("pw-1").value;
      if (a.length < 8) { ev.preventDefault(); $("pw-err").textContent = "Use at least 8 characters."; return; }
      if (confirm && a !== $("pw-2").value) { ev.preventDefault(); $("pw-err").textContent = "Passphrases do not match."; return; }
    };
    form.addEventListener("submit", onSubmit);
    d.addEventListener("close", () => {
      form.removeEventListener("submit", onSubmit);
      res(d.returnValue === "ok" ? { pass: $("pw-1").value, remember: $("pw-remember").checked } : null);
    }, { once: true });
  });
}

// ------------------------------------------------------------------ keys
function storedKeyfile() {
  try { return localStorage.getItem(STORE_KEY); } catch (_) { return null; }
}

function showRemembered() {
  const text = storedKeyfile();
  let label = null;
  try { label = text ? JSON.parse(text).public.label : null; } catch (_) { /* ignore */ }
  $("remembered").hidden = !label;
  if (label) $("remembered-label").textContent = label;
}

function render(st) {
  const has = !!(st && st.has_keys);
  $("keys-empty").hidden = has;
  $("keys-loaded").hidden = !has;
  $("wm-go").disabled = !has || !wmFile;
  $("dt-go").disabled = !(st && st.pattern_keys && st.pattern_keys.length) || !dtFile;
  state = st;
  if (!has) return;
  $("id-label").textContent = st.label;
  $("id-fp").textContent = st.fingerprint;
  $("unsaved").hidden = !unsaved;
  const items = st.trusted.map((t) => `<li><span><b>${esc(t.label)}</b> <span class="mono small-text">${esc(t.key_id)}</span>${t.own ? " (you)" : ""}</span>${t.own ? "" : `<button class="link" data-remove="${esc(t.key_id)}">Remove</button>`}</li>`);
  for (const p of st.pattern_keys.slice(1)) items.push(`<li><span>Pattern key <b>${esc(p.label)}</b> <span class="mono small-text">${esc(p.key_id)}</span></span></li>`);
  $("trust-list").innerHTML = items.join("");
}
let state = null;

async function refreshSession() {
  // Re-encrypt the in-memory session copy after keys change (Argon2id: ~1-2 s).
  const pass = crypto.getRandomValues(new Uint32Array(8)).join("-");
  session = { text: await call("save_keyfile", { passphrase: pass }), pass };
}

async function guarded(btn, fn) {
  btn.disabled = true;
  try { await fn(); } catch (e) { alert(e.message); } finally { btn.disabled = false; }
}

$("btn-generate").onclick = () => guarded($("btn-generate"), async () => {
  const name = await askName();
  if (!name) return;
  render(await call("generate_keys", { label: name }));
  unsaved = true;
  render(state);
  await refreshSession();
});

$("btn-open").onclick = () => $("keyfile-input").click();
$("keyfile-input").onchange = async (ev) => {
  const f = ev.target.files[0];
  ev.target.value = "";
  if (!f) return;
  const text = await f.text();
  let label = "this keyfile";
  try { label = JSON.parse(text).public.label; } catch (_) { alert("This is not a Veilmark keyfile."); return; }
  await unlock(text, `Enter the passphrase for ${label}.`, true);
};

async function unlock(text, msg, offerRemember) {
  for (;;) {
    const r = await askPassphrase({ title: "Unlock keys", text: msg + " Unlocking takes a few seconds.", confirm: false, remember: offerRemember });
    if (!r) return;
    try {
      render(await call("load_keyfile", { text, passphrase: r.pass }));
      session = { text, pass: r.pass };
      unsaved = false;
      render(state);
      if (r.remember) { try { localStorage.setItem(STORE_KEY, text); } catch (_) { /* storage unavailable */ } }
      showRemembered();
      return;
    } catch (e) {
      msg = e.message + ".";
    }
  }
}

$("btn-unlock").onclick = () => {
  const text = storedKeyfile();
  if (text) unlock(text, "Enter your passphrase.", false);
};
$("btn-forget-device").onclick = () => {
  if (!confirm("Delete the encrypted copy stored in this browser? Make sure you have your keyfile.")) return;
  try { localStorage.removeItem(STORE_KEY); } catch (_) { /* ignore */ }
  showRemembered();
};

$("btn-save").onclick = () => guarded($("btn-save"), async () => {
  const r = await askPassphrase({
    title: "Save keyfile",
    text: "The keyfile contains your private signing key and pattern key, encrypted with this passphrase. Without the passphrase it cannot be opened, and nobody can recover it for you.",
    confirm: true, remember: true,
  });
  if (!r) return;
  const text = await call("save_keyfile", { passphrase: r.pass });
  const name = `veilmark-${(state.label || "keys").replace(/[^\w.-]+/g, "_")}.vmkey.json`;
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  if (r.remember) { try { localStorage.setItem(STORE_KEY, text); } catch (_) { /* ignore */ } }
  session = { text, pass: r.pass };
  unsaved = false;
  render(state);
  showRemembered();
});

$("btn-copy-pub").onclick = async () => {
  try { await navigator.clipboard.writeText(state.public_line); $("btn-copy-pub").textContent = "Copied"; }
  catch (_) { prompt("Your public key:", state.public_line); }
  setTimeout(() => ($("btn-copy-pub").textContent = "Copy public key"), 1500);
};

$("btn-close-keys").onclick = async () => {
  if (unsaved && !confirm("These keys have not been saved. Close them anyway? They will be lost.")) return;
  session = null; unsaved = false;
  render(await call("forget_keys"));
};

$("btn-trust-add").onclick = () => guarded($("btn-trust-add"), async () => {
  render(await call("add_trusted", { line: $("trust-line").value, label: "" }));
  $("trust-line").value = "";
  unsaved = true; render(state);
  await refreshSession();
});
$("btn-pattern-add").onclick = () => guarded($("btn-pattern-add"), async () => {
  render(await call("add_pattern_key", { line: $("pattern-line").value, label: "" }));
  $("pattern-line").value = "";
  unsaved = true; render(state);
  await refreshSession();
});
$("trust-list").onclick = async (ev) => {
  const id = ev.target?.dataset?.remove;
  if (!id) return;
  render(await call("remove_trusted", { key_id: id }));
  unsaved = true; render(state);
  await refreshSession();
};

window.addEventListener("beforeunload", (ev) => {
  if (unsaved) { ev.preventDefault(); ev.returnValue = ""; }
});

// ------------------------------------------------------------------ files
let wmFile = null;
let dtFile = null;

function wireDrop(dropId, inputId, onFile) {
  const d = $(dropId), inp = $(inputId);
  d.onclick = () => inp.click();
  d.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); inp.click(); } };
  inp.onchange = () => inp.files[0] && onFile(inp.files[0], d);
  d.ondragover = (e) => { e.preventDefault(); d.classList.add("over"); };
  d.ondragleave = () => d.classList.remove("over");
  d.ondrop = (e) => { e.preventDefault(); d.classList.remove("over"); e.dataTransfer.files[0] && onFile(e.dataTransfer.files[0], d); };
}

function showFile(d, f) {
  const url = URL.createObjectURL(f);
  d.innerHTML = `<img alt="" src="${url}"><small>${esc(f.name)} · ${(f.size / 1e6).toFixed(1)} MB</small>`;
}

wireDrop("wm-drop", "wm-file", (f, d) => {
  wmFile = f; showFile(d, f); $("wm-out").innerHTML = "";
  $("wm-rewm").checked = false; $("wm-rewm-row").hidden = true; render(state);
});
wireDrop("dt-drop", "dt-file", (f, d) => { dtFile = f; showFile(d, f); $("dt-out").innerHTML = ""; render(state); });
$("wm-text").oninput = () => ($("wm-count").textContent = `${new TextEncoder().encode($("wm-text").value).length} / 60`);

// ------------------------------------------------------------------- jobs
function job(prefix) {
  const box = $(`${prefix}-job`), fill = $(`${prefix}-fill`), msg = $(`${prefix}-msg`), time = $(`${prefix}-time`);
  const t0 = Date.now();
  box.hidden = false;
  fill.style.width = "2%";
  msg.textContent = "Starting…";
  const timer = setInterval(() => (time.textContent = `${Math.round((Date.now() - t0) / 1000)} s`), 250);
  return {
    progress: (f, m) => { fill.style.width = `${Math.max(2, Math.round(f * 100))}%`; msg.textContent = m; },
    end: () => { clearInterval(timer); box.hidden = true; time.textContent = ""; },
  };
}

$("wm-cancel").onclick = $("dt-cancel").onclick = () => restartWorker();

$("wm-go").onclick = async () => {
  const btn = $("wm-go"), out = $("wm-out");
  btn.disabled = true; out.innerHTML = "";
  const j = job("wm");
  try {
    const data = await wmFile.arrayBuffer();
    const fmt = $("wm-format").value;
    const r = await call("embed", {
      data, name: wmFile.name, text: $("wm-text").value, strength: $("wm-strength").value,
      format: fmt, quality: 92, sign: true, self_check: $("wm-selfcheck").checked,
      allow_rewatermark: $("wm-rewm").checked,
    }, j.progress, [data]);
    const res = r.result;
    const blob = new Blob([r.output], { type: res.mime });
    const outUrl = URL.createObjectURL(blob);
    const origUrl = URL.createObjectURL(wmFile);
    const sc = res.extra.self_check;
    const check = !sc ? "" : sc.payload_recoverable
      ? `<span class="pill ok">read-back check passed</span>` : `<span class="pill bad">read-back check FAILED</span>`;
    out.innerHTML = `
      <div class="row wrap">${check}<span class="small-text">PSNR ${esc(res.psnr_db)} dB · SSIM ${esc(res.ssim)} · ${esc(res.payload_bytes)}-byte signed payload</span></div>
      <div class="compare" id="cmp" title="Press and hold to see the original · click to zoom to 100%">
        <span class="badge" id="cmp-badge">watermarked · hold to compare</span><img id="cmp-img" alt="Watermarked result" src="${outUrl}">
      </div>
      ${(res.notes || []).map((n) => `<p class="${n.startsWith("SELF-CHECK") ? "err" : "small-text"}">${esc(n)}</p>`).join("")}
      <p class="small-text">Watermark id <span class="mono">${esc(res.watermark_id)}</span></p>
      <a class="download" href="${outUrl}" download="${esc(res.output_name)}"><button class="primary">Download ${esc(res.output_name)}</button></a>`;
    const cmp = $("cmp"), img = $("cmp-img"), badge = $("cmp-badge");
    const show = (orig) => { img.src = orig ? origUrl : outUrl; badge.textContent = orig ? "original" : "watermarked · hold to compare"; };
    cmp.onpointerdown = () => show(true);
    cmp.onpointerup = cmp.onpointerleave = () => show(false);
    cmp.ondblclick = cmp.onclick = (e) => { if (e.detail >= 1) cmp.classList.toggle("zoom"); };
  } catch (e) {
    if (e.message !== "cancelled") out.innerHTML = `<p class="err">${esc(e.message)}</p>`;
    // Offer the explicit override only after the refusal has been shown.
    if (e.message.includes("already carries a Veilmark watermark")) $("wm-rewm-row").hidden = false;
  } finally {
    j.end(); btn.disabled = false; render(state);
  }
};

const ST = { "payload-recovered": ["Watermark found", "ok"], "id-only": ["Watermark id only", "warn"],
  "signal-only": ["Signal found, text unreadable", "warn"], "not-detected": ["No watermark found", "na"] };
const SIG = { valid: ["valid", "ok"], invalid: ["INVALID: altered or forged", "bad"], unsigned: ["unsigned", "warn"],
  "unknown-key": ["unknown key", "warn"], unverifiable: ["cannot be checked", "warn"] };
const TR = { trusted: ["trusted", "ok"], untrusted: ["not in your trust list", "bad"], revoked: ["revoked", "bad"],
  expired: ["expired", "bad"], "not-yet-valid": ["not yet valid", "bad"], "n/a": ["n/a", "na"] };
const pill = ([t, c]) => `<span class="pill ${c}">${esc(t)}</span>`;

$("dt-go").onclick = async () => {
  const btn = $("dt-go"), out = $("dt-out");
  btn.disabled = true; out.innerHTML = "";
  const j = job("dt");
  try {
    const data = await dtFile.arrayBuffer();
    const r = await call("detect", { data, name: dtFile.name, thorough: $("dt-thorough").checked }, j.progress, [data]);
    const v = r.verification;
    let h = `<div class="verdict"><div class="line"><span class="k">Detection</span>${pill(ST[r.status] || [r.status, "na"])}</div>`;
    if (v) {
      h += `<div class="line"><span class="k">Signature</span>${pill(SIG[v.signature] || [v.signature, "na"])}</div>`;
      h += `<div class="line"><span class="k">Issuer</span><span>${v.issuer_label ? esc(v.issuer_label) + " " : ""}${pill(TR[v.trust] || [v.trust, "na"])}</span></div>`;
    }
    h += "</div>";
    if (r.payload) {
      const p = r.payload;
      h += `<div class="payload" style="margin-top:10px">${p.text != null ? `<div><b>${esc(p.text)}</b></div>` : "<div>(no text)</div>"}
        ${p.timestamp_iso ? `<div class="small-text">Signed ${esc(new Date(p.timestamp_iso).toLocaleString())} (time claimed by the signer)</div>` : ""}</div>`;
    }
    if (v) h += `<p class="small-text" style="margin-top:8px">${esc(v.message)}</p>`;
    if (r.watermark_id) h += `<p class="small-text">Watermark id <span class="mono">${esc(r.watermark_id)}</span></p>`;
    for (const a of r.additional_watermarks || []) {
      const av = a.verification || {};
      h += `<div class="payload" style="margin-top:10px"><div class="k">Also found: another watermark</div>
        <div>${a.payload && a.payload.text != null ? `<b>${esc(a.payload.text)}</b>` : esc(a.status)}</div>
        <div class="small-text">Signature ${esc(av.signature || "n/a")} · ${esc(av.issuer_label || "unknown issuer")} · ${esc(av.trust || "")} · id ${esc(a.watermark_id || "?")}</div></div>`;
    }
    h += `<p class="small-text">Evidence: sync z = ${esc(r.confidence.sync_z)} (threshold ${esc(r.confidence.sync_present_threshold)})</p>`;
    for (const n of r.notes || []) h += `<p class="small-text">${esc(n)}</p>`;
    out.innerHTML = h;
  } catch (e) {
    if (e.message !== "cancelled") out.innerHTML = `<p class="err">${esc(e.message)}</p>`;
  } finally {
    j.end(); btn.disabled = false; render(state);
  }
};

if (!("Worker" in window) || !("WebAssembly" in window)) {
  setBoot(0, "This browser cannot run Veilmark (needs Web Workers and WebAssembly).");
} else {
  startWorker();
}
