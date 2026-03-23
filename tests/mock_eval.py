"""
Mock evaluation script for K-Veritas integration testing.

Demonstrates multi-metric evaluation output including F1, precision,
recall, and AUC. Run after mock_train.py in the same session.

Usage:
  kveritas run --files tests/mock_eval.py -- python tests/mock_eval.py
"""
import time
import random

random.seed(123)


def evaluate_model() -> dict:
    time.sleep(0.1)
    return {
        "test_accuracy": 0.9413 + random.gauss(0, 0.002),
        "test_loss": 0.1872 + random.gauss(0, 0.003),
        "f1_score": 0.9381 + random.gauss(0, 0.002),
        "precision": 0.9402 + random.gauss(0, 0.002),
        "recall": 0.9361 + random.gauss(0, 0.002),
        "auc_roc": 0.9871 + random.gauss(0, 0.001),
    }


print("Running evaluation on held-out test set...")
results = evaluate_model()

print()
print("Evaluation results:")
for name, value in results.items():
    print(f"  {name}: {value:.4f}")

print()

# Emit canonical KVERITAS_METRIC lines for all metrics.
for name, value in results.items():
    print(f"KVERITAS_METRIC name={name} value={value:.6f} step=final")

print()
print(f"Evaluation complete. {len(results)} metrics reported.")
