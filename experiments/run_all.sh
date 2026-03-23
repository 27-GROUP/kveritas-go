#!/usr/bin/env bash
# Run all mock experiments and produce signed PDF reports.
# Usage: bash experiments/run_all.sh [--server URL]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BIN="$ROOT_DIR/bin/kveritas"
SERVER="${1:-http://localhost:7433}"
REPORTS_DIR="$ROOT_DIR/reports"

mkdir -p "$REPORTS_DIR"

run_experiment() {
    local name="$1"
    local exp_dir="$2"
    shift 2
    local cmds=("$@")   # array of "label|cmd" pairs

    echo "============================================================"
    echo "Experiment: $name"
    echo "============================================================"

    cd "$exp_dir"

    # Clean up any previous session.
    rm -rf .kveritas

    "$BIN" init --server "$SERVER"

    for entry in "${cmds[@]}"; do
        label="${entry%%|*}"
        cmd="${entry#*|}"
        echo ""
        echo "--- $label ---"
        eval "$BIN run -- $cmd"
    done

    local report="$REPORTS_DIR/${name}.pdf"
    "$BIN" seal --output "$report"

    echo ""
    echo "Verifying $report ..."
    "$BIN" verify "$report"
    echo ""

    cd "$ROOT_DIR"
}

# Experiment 1: MLP Classifier
run_experiment "exp1_mlp_classifier" \
    "$SCRIPT_DIR/exp1_mlp_classifier" \
    "Training run|python3 train.py" \
    "Evaluation|python3 evaluate.py"

# Experiment 2: Gradient Boosted Regression
run_experiment "exp2_regression" \
    "$SCRIPT_DIR/exp2_regression" \
    "CV + final model|python3 train.py"

# Experiment 3: Transformer NLP
run_experiment "exp3_nlp" \
    "$SCRIPT_DIR/exp3_nlp" \
    "Fine-tuning|python3 train.py"

echo "============================================================"
echo "All experiments complete. Reports:"
ls -lh "$REPORTS_DIR/"
echo "============================================================"
