// End-to-end smoke test of the *browser* engine path under Node.js: the real Pyodide
// (WebAssembly) runtime, the built engine zip and webapp/bridge.py.
//
//   python scripts/build_webapp.py --out dist/web
//   cd tests/webapp && npm install && node smoke.mjs ../../dist/web
//
// Exits non-zero on any failure.
import { loadPyodide } from "pyodide";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const dist = process.argv[2] || "../../dist/web";
const fail = (msg) => { console.error("FAIL:", msg); process.exit(1); };
process.on("unhandledRejection", (e) => fail(String(e?.message || e).split("\n").slice(-3).join(" | ")));

const t0 = Date.now();
const py = await loadPyodide();
await py.loadPackage(["numpy", "opencv-python", "pillow", "pynacl"]);
py.unpackArchive(new Uint8Array(readFileSync(join(dist, "veilmark.zip"))), "zip", { extractDir: "/lib/vm" });
py.FS.writeFile("/lib/vm/veilmark_bridge.py", readFileSync(join(dist, "bridge.py"), "utf8"));
await py.runPythonAsync("import sys; sys.path.insert(0, '/lib/vm'); import veilmark_bridge");
console.log(`runtime ready in ${(Date.now() - t0) / 1000}s`);
const b = py.pyimport("veilmark_bridge");
const J = (x) => x.toJs({ dict_converter: Object.fromEntries, create_pyproxies: false });

// A deterministic 900x700 test image, generated in Python.
const png = J(await py.runPythonAsync(`
import io, numpy as np, cv2
from PIL import Image
rng = np.random.default_rng(3)
img = cv2.resize(rng.integers(0, 255, (44, 56, 3)).astype(np.uint8), (900, 700), interpolation=cv2.INTER_CUBIC)
img = np.clip(img + rng.normal(0, 10, img.shape), 0, 255).astype(np.uint8)
buf = io.BytesIO(); Image.fromarray(img).save(buf, "PNG"); buf.getvalue()
`));

const st = J(b.generate_keys("CI"));
if (!st.has_keys) fail("key generation");
const kf = b.save_keyfile("ci-passphrase");
if (J(b.load_keyfile(kf, "ci-passphrase")).key_id !== st.key_id) fail("keyfile roundtrip");

let ticks = 0;
const res = J(b.embed(png, "ci.png", "hello wasm", "balanced", "jpg", 92, true, true, () => ticks++));
if (!res.result.extra.self_check.payload_recoverable) fail("self-check after embedding");
if (!(res.output instanceof Uint8Array) || res.output.length < 1000) fail("output bytes");
if (ticks < 5) fail(`too few progress callbacks (${ticks})`);

const rep = J(b.detect(res.output, "ci.wm.jpg", false, () => {}));
if (rep.status !== "payload-recovered" || rep.payload.text !== "hello wasm" || !rep.authentic) {
  fail(`detection: ${rep.status} ${JSON.stringify(rep.verification)}`);
}
let refused = false;
try { b.embed(res.output, "again.jpg", "x", "balanced", "png", 92, true, false); } catch (e) { refused = /already carries/.test(e.message); }
if (!refused) fail("re-watermark was not refused");
if (J(b.detect(png, "orig.png", false, () => {})).status !== "not-detected") fail("false positive");
console.log(`OK: embed + self-check + detect + re-watermark refusal in ${(Date.now() - t0) / 1000}s`);

// Video: the frame-by-frame protocol worker.js drives (WebCodecs is not available here,
// so the luma planes are synthesised: textured content panning slowly).
const t1 = Date.now();
const W = 480, H = 352, N = 60;
const meta = { name: "ci.webm", width: W, height: H, fps: 30, duration: N / 30, frames: N, codec: "vp9", audio_codecs: [] };
await py.runPythonAsync(`
import numpy as np, cv2
rng = np.random.default_rng(5)
base = cv2.resize(rng.integers(0, 255, (60, 80)).astype(np.uint8), (${W} + ${N}, ${H}), interpolation=cv2.INTER_CUBIC)
base = np.clip(base + rng.normal(0, 8, base.shape), 0, 255).astype(np.uint8)
ci_frames = [np.ascontiguousarray(base[:, i:i + ${W}]) for i in range(${N})]
`);
const original = [];
for (let i = 0; i < N; i++) original.push(J(py.runPython(`ci_frames[${i}].tobytes()`)));
const answer = (req, frames) => {
  for (;;) {
    let taken = 0;
    for (let n = 0; n < frames.length && taken < req.max_frames; n++) {
      if (n % req.stride < Math.max(1, Math.min(req.run_length, req.stride))) { b.video_frame(frames[n]); taken++; }
    }
    const r = J(b.video_frames_end());
    if (r.report) return r.report;
    req = r.request;
  }
};
let vticks = 0;
const check = answer(J(b.video_embed_begin(meta, "wasm video", "robust", "robust", false, false, true, () => vticks++)), original);
if (check.status !== "not-detected") fail(`video existing-watermark check: ${check.status}`);
const wid = J(b.video_embed_start()).watermark_id;
const marked = original.map((y) => { const o = b.video_embed_frame(y); const a = o.toJs(); o.destroy(); return a; });
const vres = J(b.video_embed_finish("ci.wm.webm", 12345, []));
if (vres.watermark_id !== wid || vres.extra.frames !== N) fail("video embed result");
answer(J(b.video_self_check_begin(meta)), marked);
const vchk = J(b.video_self_check_result());
if (!vchk.extra.self_check.payload_recoverable) fail(`video read-back: ${vchk.extra.self_check.status}`);
const vrep = answer(J(b.video_detect_begin(meta, () => {})), marked);
if (vrep.status !== "payload-recovered" || vrep.payload.text !== "wasm video" || !vrep.authentic) fail(`video detection: ${vrep.status}`);
if (vticks < 5) fail(`too few video progress callbacks (${vticks})`);
console.log(`OK: video embed + read-back + detect (${N} frames ${W}x${H}) in ${(Date.now() - t1) / 1000}s`);
