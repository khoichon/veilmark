#!/usr/bin/env bash
# Reproduce the benchmark reports shipped in benchmarks/results/.
# Usage: scripts/run_benchmarks.sh [output-dir]
# Takes roughly 1-2 hours on an 8-10 core machine. Requires the `bench` extra
# (scikit-image sample data) and ffmpeg for the video runs.
set -euo pipefail
OUT="${1:-benchmarks/results}"
VM="${VEILMARK:-veilmark}"
"$VM" benchmark --split heldout --profile standard --media image --out "$OUT/image-heldout"
"$VM" benchmark --split dev     --profile standard --media image --out "$OUT/image-dev"
"$VM" benchmark --split heldout --profile standard --media image --strength 0.6 --out "$OUT/image-heldout-subtle"
"$VM" benchmark --split heldout --profile standard --media video --out "$OUT/video-heldout"
"$VM" benchmark --split dev     --profile standard --media video --out "$OUT/video-dev"
