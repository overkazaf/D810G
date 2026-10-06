#!/bin/bash
# Record all D810G demo sessions as SVG animations
# Requires: termtosvg (pip install termtosvg)

set -e
cd "$(dirname "$0")/.."

OUTDIR="docs/assets/recordings"
mkdir -p "$OUTDIR"

export PYTHONPATH="$PWD/python"

echo "=== Recording D810G demos as SVG animations ==="

# 1. MBA Simplification
echo "[1/5] Recording MBA demo..."
termtosvg "$OUTDIR/mba.svg" -g 90x24 -t window_frame_js -c bash\ -c\ '
echo "$ d810g cli simplify \"(x | y) - (x & y)\""
python -m d810g_engine cli simplify "(x | y) - (x & y)"
echo
echo "$ d810g cli simplify \"(x & ~y) | (~x & y)\""
python -m d810g_engine cli simplify "(x & ~y) | (~x & y)"
echo
echo "$ d810g cli simplify --deep \"((x | y) - (x & y)) ^ ((x | y) - (x & y))\""
python -m d810g_engine cli simplify --deep "((x | y) - (x & y)) ^ ((x | y) - (x & y))"
sleep 1
'

# 2. Opaque Predicates
echo "[2/5] Recording Opaque Predicate demo..."
termtosvg "$OUTDIR/opaque.svg" -g 90x20 -t window_frame_js -c bash\ -c\ '
echo "$ d810g cli opaque \"x == x\""
python -m d810g_engine cli opaque "x == x"
echo
echo "$ d810g cli opaque \"(x & 1) == 2\""
python -m d810g_engine cli opaque "(x & 1) == 2"
echo
echo "$ d810g cli opaque \"x > 5\""
python -m d810g_engine cli opaque "x > 5"
sleep 1
'

# 3. Rules listing
echo "[3/5] Recording Rules demo..."
termtosvg "$OUTDIR/rules.svg" -g 90x30 -t window_frame_js -c bash\ -c\ '
echo "$ d810g cli rules"
python -m d810g_engine cli rules
sleep 1
'

# 4. Full demo run
echo "[4/5] Recording Demo suite..."
termtosvg "$OUTDIR/demo_mba_full.svg" -g 90x30 -t window_frame_js -c bash\ -c\ '
python demo/demo_mba.py 2>&1 | head -50
sleep 1
'

# 5. Test suite
echo "[5/5] Recording test run..."
termtosvg "$OUTDIR/tests.svg" -g 90x20 -t window_frame_js -c bash\ -c\ '
echo "$ python -m pytest test/ -q"
python -m pytest test/ -q
sleep 1
'

echo
echo "=== All recordings saved to $OUTDIR/ ==="
ls -la "$OUTDIR"/*.svg
