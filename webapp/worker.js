// Veilmark web worker: runs the Python engine (Pyodide) off the main thread so the
// page stays responsive and can show live progress.
//
// Protocol (main -> worker):  {id, op, args}
//           (worker -> main): {type: "boot", f, msg} | {type: "ready", info}
//                             {type: "progress", id, f, msg}
//                             {type: "result", id, value} | {type: "error", id, message}

import * as MB from "./vendor/mediabunny-1.65.2.min.mjs";

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
      new Uint8Array(a.data), a.name, a.text, a.strength, a.format, a.quality, a.sign, a.self_check, progress, !!a.allow_rewatermark, !!a.public,
    ),
  detect: (a, progress) => bridge.detect(new Uint8Array(a.data), a.name, a.thorough, progress),
  video_detect: (a, progress) => videoDetect(a.file, progress),
  video_embed: (a, progress) => videoEmbed(a, progress),
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
    let value = toJs(await fn(args || {}, progress));
    const transfer = [];
    if (value && value.output instanceof Uint8Array) transfer.push(value.output.buffer);
    postMessage({ type: "result", id, value }, transfer);
  } catch (e) {
    postMessage({ type: "error", id, message: friendly(e) });
  }
};

// ------------------------------------------------------------------ video
// Decoding and encoding use the browser's WebCodecs through Mediabunny; Python only sees
// luma planes, one frame at a time (see "video" in bridge.py).

function videoSupported() {
  if (typeof VideoDecoder === "undefined" || typeof VideoFrame === "undefined") {
    throw new Error("this browser cannot process video (no WebCodecs); use a current Chrome, Edge, Safari or Firefox, or the desktop app");
  }
}

function openInput(src) {
  const source = src instanceof Blob ? new MB.BlobSource(src) : new MB.BufferSource(src);
  return new MB.Input({ source, formats: MB.ALL_FORMATS });
}

// Track facts the engine needs. Width and height are those of the decoded frames (coded
// orientation: rotation stays metadata, as the frames are processed unrotated).
async function probe(input, name) {
  const track = await input.getPrimaryVideoTrack();
  if (!track) throw new Error("no video track found");
  if (!(await track.canDecode())) throw new Error(`this browser cannot decode ${track.codec || "this"} video`);
  const sink = new MB.VideoSampleSink(track);
  const first = await sink.getSample(await track.getFirstTimestamp());
  if (!first) throw new Error("no frames could be decoded from the video");
  const { width, height } = first.visibleRect;
  first.close();
  const duration = await track.computeDuration();
  const stats = await track.computePacketStats();
  const audio = await input.getAudioTracks();
  return {
    track,
    meta: {
      name, width, height, duration,
      fps: stats.averagePacketRate || 30,
      frames: stats.packetCount || null,
      codec: track.codec || "?",
      rotation: track.rotation || 0,
      audio_codecs: audio.map((t) => t.codec || "?"),
    },
  };
}

// Pixel data of one frame as tightly packed planes with the luma plane first.
// I420 and NV12 (what decoders normally produce) are copied as they are; anything else
// is converted from RGBA to I420 here (BT.709, limited range).
async function readFrame(sample, w, h) {
  const rect = sample.visibleRect;
  if (rect.width !== w || rect.height !== h) throw new Error("the frame size changes within the video; this is not supported");
  const cw = (w + 1) >> 1, ch = (h + 1) >> 1, ys = w * h;
  const fmt = sample.format;
  if (fmt === "I420" || fmt === "NV12") {
    const layout = fmt === "I420"
      ? [{ offset: 0, stride: w }, { offset: ys, stride: cw }, { offset: ys + cw * ch, stride: cw }]
      : [{ offset: 0, stride: w }, { offset: ys, stride: 2 * cw }];
    const data = new Uint8Array(ys + 2 * cw * ch);
    await sample.copyTo(data, { rect, layout });
    return { format: fmt, data, colorSpace: sample.colorSpace.toJSON() };
  }
  const rgba = new Uint8Array(w * h * 4);
  try {
    await sample.copyTo(rgba, { rect, format: "RGBA", colorSpace: "srgb" });
  } catch (_) {
    const canvas = new OffscreenCanvas(w, h), ctx = canvas.getContext("2d");
    const vf = sample.toVideoFrame();
    try { ctx.drawImage(vf, rect.x, rect.y, w, h, 0, 0, w, h); } finally { vf.close(); }
    rgba.set(ctx.getImageData(0, 0, w, h).data);
  }
  return { format: "I420", data: rgbaToI420(rgba, w, h), colorSpace: { primaries: "bt709", transfer: "bt709", matrix: "bt709", fullRange: false } };
}

function rgbaToI420(px, w, h) {
  const cw = (w + 1) >> 1, ch = (h + 1) >> 1, ys = w * h;
  const out = new Uint8Array(ys + 2 * cw * ch);
  for (let i = 0, j = 0; i < ys; i++, j += 4) {
    out[i] = 16 + ((46.559 * px[j] + 156.629 * px[j + 1] + 15.812 * px[j + 2]) / 255 + 0.5) | 0;
  }
  for (let cy = 0; cy < ch; cy++) {
    for (let cx = 0; cx < cw; cx++) {
      let r = 0, g = 0, b = 0, n = 0;
      for (let dy = 0; dy < 2; dy++) for (let dx = 0; dx < 2; dx++) {
        const x = 2 * cx + dx, y = 2 * cy + dy;
        if (x < w && y < h) { const j = 4 * (y * w + x); r += px[j]; g += px[j + 1]; b += px[j + 2]; n++; }
      }
      r /= n; g /= n; b /= n;
      const k = cy * cw + cx;
      out[ys + k] = 128 + ((-25.664 * r - 86.336 * g + 112 * b) / 255 + 0.5) | 0;
      out[ys + cw * ch + k] = 128 + ((112 * r - 101.730 * g - 10.270 * b) / 255 + 0.5) | 0;
    }
  }
  return out;
}

// Answer the detector's frame requests until it returns a report. Frame n (presentation
// order) is wanted when n % stride < run_length, as with ffmpeg's select filter.
async function answerRequests(src, req) {
  for (;;) {
    const input = openInput(src);
    try {
      const track = await input.getPrimaryVideoTrack();
      let size = null, n = 0, taken = 0;
      const run = Math.max(1, Math.min(req.run_length, req.stride));
      for await (const sample of new MB.VideoSampleSink(track).samples()) {
        try {
          if (n % req.stride < run) {
            size ??= [sample.visibleRect.width, sample.visibleRect.height];
            const f = await readFrame(sample, size[0], size[1]);
            bridge.video_frame(f.data.subarray(0, size[0] * size[1]));
            taken += 1;
          }
        } finally {
          sample.close();
        }
        n += 1;
        if (taken >= req.max_frames) break;
      }
    } finally {
      input.dispose?.();
    }
    const r = toJs(bridge.video_frames_end());
    if (r.report) return r.report;
    req = r.request;
  }
}

async function videoDetect(file, progress) {
  videoSupported();
  const input = openInput(file);
  const { meta } = await probe(input, file.name);
  input.dispose?.();
  return answerRequests(file, toJs(bridge.video_detect_begin(meta, progress)));
}

const CONTAINERS = [
  [MB.MP4, () => new MB.Mp4OutputFormat({ fastStart: "in-memory" }), "mp4", "video/mp4"],
  [MB.QTFF, () => new MB.MovOutputFormat({ fastStart: "in-memory" }), "mov", "video/quicktime"],
  [MB.WEBM, () => new MB.WebMOutputFormat(), "webm", "video/webm"],
  [MB.MATROSKA, () => new MB.MkvOutputFormat(), "mkv", "video/x-matroska"],
];

async function videoEmbed(a, progress) {
  videoSupported();
  if (typeof VideoEncoder === "undefined") throw new Error("this browser cannot encode video (no WebCodecs VideoEncoder)");
  const file = a.file;
  const probeInput = openInput(file);
  const { meta } = await probe(probeInput, file.name);
  const inFormat = await probeInput.getFormat();
  probeInput.dispose?.();
  const req = toJs(bridge.video_embed_begin(meta, a.text, a.strength, a.mode || "robust", !!a.public, !!a.allow_rewatermark, !!a.self_check, progress));
  await answerRequests(file, req);
  const { watermark_id } = toJs(bridge.video_embed_start());

  const [, makeFormat, ext, mime] = CONTAINERS.find(([f]) => f === inFormat) || CONTAINERS[0];
  const input = openInput(file);
  const target = new MB.BufferTarget();
  const output = new MB.Output({ format: makeFormat(), target });
  const { width: w, height: h } = meta;
  // Frames must reach the engine one at a time and in order (its schedule is per frame).
  let chain = Promise.resolve();
  const processFrame = async (sample) => {
    const f = await readFrame(sample, w, h);
    const y2 = bridge.video_embed_frame(f.data.subarray(0, w * h));
    f.data.set(y2.toJs(), 0);
    y2.destroy();
    return new MB.VideoSample(f.data, {
      format: f.format, codedWidth: w, codedHeight: h,
      timestamp: sample.timestamp, duration: sample.duration, colorSpace: f.colorSpace,
    });
  };
  const conv = await MB.Conversion.init({
    input, output, showWarnings: false,
    video: {
      forceTranscode: true,
      quality: MB.QUALITY_VERY_HIGH,
      process: (sample) => (chain = chain.then(() => processFrame(sample))),
    },
  });
  const notes = [];
  for (const d of conv.discardedTracks) {
    if (d.track.isVideoTrack() && d.track === (await input.getPrimaryVideoTrack())) {
      throw new Error(`this browser cannot write ${ext.toUpperCase()} video (${d.reason})`);
    }
    if (d.track.isAudioTrack()) notes.push(`an audio track (${d.track.codec || "unknown codec"}) was dropped: ${d.reason}`);
  }
  if (!conv.isValid) throw new Error("this browser cannot convert this video");
  await conv.execute();
  const buf = target.buffer;
  const stem = file.name.replace(/\.[^.]*$/, "") || "video";
  const name = `${stem}.wm.${ext}`;
  let result = toJs(bridge.video_embed_finish(name, buf.byteLength, notes));
  if (a.self_check) {
    const outInput = openInput(buf);
    const { meta: outMeta } = await probe(outInput, name);
    outInput.dispose?.();
    await answerRequests(buf, toJs(bridge.video_self_check_begin(outMeta)));
    result = toJs(bridge.video_self_check_result());
  }
  if (result.watermark_id !== watermark_id) throw new Error("internal error: watermark id mismatch");
  result.mime = mime;
  return { result, output: new Uint8Array(buf) };
}
