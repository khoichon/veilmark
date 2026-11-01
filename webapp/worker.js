// Veilmark web worker: runs the Python engine (Pyodide) off the main thread so the
// page stays responsive and can show live progress.
//
// Protocol (main -> worker):  {id, op, args}
//           (worker -> main): {type: "boot", f, msg} | {type: "ready", info}
//                             {type: "progress", id, f, msg}
//                             {type: "result", id, value} | {type: "error", id, message}

const PYODIDE_VERSION = "314.0.7";
const PACKAGES = ["numpy", "opencv-python", "pillow", "pynacl"];

let py = null;
let bridge = null;

function boot(f, msg) {
  postMessage({ type: "boot", f, msg });
}

async function config() {
  try {
    const r = await fetch("config.json", { cache: "no-store" });
    if (r.ok) return await r.json();
  } catch (_) {
    /* fall through to defaults */
  }
  return {};
}

async function start() {
  const cfg = await config();
  const base = cfg.pyodide_base || `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;
  boot(0.02, "Downloading the Python runtime…");
  const { loadPyodide } = await import(base + "pyodide.mjs");
  py = await loadPyodide({ indexURL: base });
  boot(0.3, "Downloading image libraries (NumPy, OpenCV, Pillow, libsodium)…");
  let loaded = 0;
  await py.loadPackage(PACKAGES, {
    messageCallback: (m) => {
      if (m.startsWith("Loaded")) {
        loaded += 1;
        boot(0.3 + 0.5 * Math.min(1, loaded / PACKAGES.length), m);
      }
    },
    errorCallback: (m) => boot(0.3, m),
  });
  boot(0.85, "Loading the Veilmark engine…");
  const zip = await (await fetch("veilmark.zip")).arrayBuffer();
  py.unpackArchive(new Uint8Array(zip), "zip", { extractDir: "/lib/veilmark-src" });
  const bridgeSrc = await (await fetch("bridge.py")).text();
  py.FS.writeFile("/lib/veilmark-src/veilmark_bridge.py", bridgeSrc);
  boot(0.92, "Starting…");
  await py.runPythonAsync(`
import sys
sys.path.insert(0, "/lib/veilmark-src")
import veilmark_bridge
`);
  bridge = py.pyimport("veilmark_bridge");
  const version = py.runPython("import veilmark; veilmark.__version__");
  postMessage({ type: "ready", info: { version, pyodide: py.version } });
}

function toJs(x) {
  if (x && typeof x.toJs === "function") {
    const v = x.toJs({ dict_converter: Object.fromEntries, create_pyproxies: false });
    x.destroy?.();
    return v;
  }
  return x;
}

function friendly(err) {
  const text = String(err && err.message ? err.message : err);
  // Python tracebacks end with "ExceptionType: message"; show only that line.
  const lines = text.trim().split("\n").filter((l) => l.trim());
  const last = lines[lines.length - 1] || text;
  return last.replace(/^[\w.]*(Error|Exception|Cancelled)\s*:\s*/, "");
}

const OPS = {
  status: () => bridge.status(),
  generate_keys: (a) => bridge.generate_keys(a.label),
  peek_keyfile: (a) => bridge.peek_keyfile(a.text),
  load_keyfile: (a) => bridge.load_keyfile(a.text, a.passphrase),
  save_keyfile: (a) => bridge.save_keyfile(a.passphrase),
  forget_keys: () => bridge.forget_keys(),
  add_trusted: (a) => bridge.add_trusted(a.line, a.label),
  remove_trusted: (a) => bridge.remove_trusted(a.key_id),
  add_pattern_key: (a) => bridge.add_pattern_key(a.line, a.label),
  export_pattern_line: () => bridge.export_pattern_line(),
  embed: (a, progress) =>
    bridge.embed(
      new Uint8Array(a.data), a.name, a.text, a.strength, a.format, a.quality, a.sign, a.self_check, progress, !!a.allow_rewatermark,
    ),
  detect: (a, progress) => bridge.detect(new Uint8Array(a.data), a.name, a.thorough, progress),
};

const ready = start().catch((e) => {
  postMessage({ type: "fatal", message: friendly(e) });
  throw e;
});

onmessage = async (ev) => {
  const { id, op, args } = ev.data;
  try {
    await ready;
    const fn = OPS[op];
    if (!fn) throw new Error(`unknown operation ${op}`);
    let last = 0;
    const progress = (f, msg) => {
      const now = Date.now();
      if (now - last > 60 || f >= 1) {
        last = now;
        postMessage({ type: "progress", id, f, msg });
      }
    };
    let value = toJs(fn(args || {}, progress));
    const transfer = [];
    if (value && value.output instanceof Uint8Array) transfer.push(value.output.buffer);
    postMessage({ type: "result", id, value }, transfer);
  } catch (e) {
    postMessage({ type: "error", id, message: friendly(e) });
  }
};
