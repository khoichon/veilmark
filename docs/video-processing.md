# Video processing

## Pipeline and preservation

* Decoding/encoding use the `ffmpeg`/`ffprobe` executables with argument lists (no
  shell). Paths that look like options or protocols are passed as `file:` URLs.
* Frames stream through pipes one at a time as `yuv420p`; only the Y plane is
  modified and chroma bytes pass through untouched. Memory is bounded by a few frames
  plus three cached pattern planes.
* **Audio**: all audio streams are copied when the container supports the codec,
  otherwise re-encoded (AAC for MP4/MOV, Opus for WebM). `--audio none|copy|aac|opus`.
* **Timing**: output uses the source's average frame rate; frame count and duration
  are preserved for constant-frame-rate sources (tested). Variable-frame-rate sources
  are re-timed to constant rate (a note is emitted).
* **Rotation**: display-matrix rotation is applied to the pixels (output is upright and
  carries no rotation flag).
* **Metadata**: container metadata and chapters are copied (`-map_metadata`), colour
  primaries/transfer/matrix/range flags are carried over.
* **Codecs**: H.264 (default, CRF 18), H.265, VP9 (default for `.webm`, CRF 24), AV1
  (SVT); `--crf`, `--bitrate`, `--preset`. Re-encoding is unavoidable when pixels change.
* Output is written to `.veilmark-*.partial.<ext>` next to the destination and renamed
  on success; cancellation or errors delete it (tested). `veilmark cleanup` removes
  leftovers from crashes.

## Moving spatial distribution

Each pattern key has 8 *variants*; they differ in sync pattern, spreading signs,
chip-to-bit permutation, cyclic chip offset and template. The keyed schedule
(`video/schedule.py`, derived from the pattern key and watermark id) splits the video
into segments of pseudo-random length and assigns each a variant different from the
previous one, cross-fading over a few frames with energy-preserving cos/sin weights.

Consequences (measured where stated):

* A fixed crop sees different chips of every coded bit over time.
* Static-scene content folds identically every frame while the watermark changes, so
  subtracting the temporal mean tile removes host interference: raw bit errors on a
  static scene fell from 13–18% to 0–0.5%.
* Naive temporal averaging (an estimation attack against a static video watermark)
  mixes independent patterns instead of reinforcing one. An attacker who clusters
  frames by variant can still estimate each pattern; this raises the bar only.

Modes: `robust` (segments 0.5–1.2 s, strength 1.0) favours short surviving clips;
`light` (segments 1.5–3 s, strength 0.75) lowers distortion and relies on longer
accumulation.

## Detection

1. **Geometry pass**: 8 runs of 4 consecutive frames across the clip. The mean frame
   is subtracted (static background), whitened spectra are averaged, and a *joint*
   template search over the lines of all variants proposes lattices. Each is scored by
   temporally accumulated sync (whole-clip coherent sum for fixed crops, per-run sums
   for moving crops), with the mean tile removed. The best is refined on its best run.
2. **Fold pass**: up to `--max-frames` (default 900) evenly sampled frames are folded
   with a precomputed index map into 128 x 128 tiles (stored as float16: ~32 KB/frame).
3. **Alignment**: per-frame sync surfaces (max over variants). If a global peak
   explains ≥80% of frames → fixed crop. Otherwise a Viterbi tracker finds the peak
   trajectory (≤6 samples of motion per frame), and each frame is aligned with a
   motion-compensated ±4-frame window. The tracked statistic is biased upward under
   noise, so it is calibrated against 3 decoy keys run through the same procedure
   (negatives: 3.9–4.7 after calibration vs 6–8.9 raw).
4. **Variant segmentation**: a Viterbi pass over per-frame variant scores with a
   switching penalty labels frames (variants change rarely), tolerating dropped,
   duplicated, reordered or trimmed frames.
5. **Accumulation**: aligned chip spectra are summed per variant, despread with pilot
   MRC, combined across variants, and turbo-decoded once.

## Performance (this machine: Apple M-series, 10 cores)

* Embedding 720p60: ~55–65 frames/s including x264 encode (10 s clip in ~11–15 s).
* Detection: ~1.5–3 s per second of 720p video at the default 900-frame cap; longer
  videos are sampled (stride) so cost is bounded.
* Measured numbers per attack are in the benchmark report.

## Limits

* Minimum ~128 px short side; small or heavily downscaled frames reduce capacity.
* Clips shorter than ~0.5 s may not carry enough evidence for the signed payload.
* Strong temporal denoisers, frame interpolation and screen re-recording are untested
  or unsupported.
* A moving crop *combined with* rescaling on low-signal footage can defeat geometry
  estimation (observed on a 3 s game-capture clip: correct geometry forced → payload
  recovered; blind search → not detected).
* Binary black/white graphics carry almost no signal (headroom rule); embedding warns.
