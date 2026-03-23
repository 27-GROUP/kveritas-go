"""
Mock training script for K-Veritas integration testing.

Demonstrates the KVERITAS_METRIC protocol: one line per metric per step.
The format is parsed by the kveritas runner in real-time and anchored
to its position in the hashed stdout stream.

Usage:
  kveritas run --files tests/mock_train.py -- python tests/mock_train.py
"""
import time
import math
import random

random.seed(42)

EPOCHS = 10
SAMPLES = 1000
LR = 0.001


def fake_loss(epoch: int, base: float = 1.4, decay: float = 0.18) -> float:
    noise = random.gauss(0, 0.01)
    return base * math.exp(-decay * epoch) + noise


def fake_accuracy(epoch: int) -> float:
    noise = random.gauss(0, 0.005)
    return min(0.99, 0.60 + 0.038 * epoch + noise)


print(f"Training config: epochs={EPOCHS}, samples={SAMPLES}, lr={LR}")
print(f"Model: 3-layer MLP, 512-256-128 units")

for epoch in range(1, EPOCHS + 1):
    time.sleep(0.05)

    train_loss = fake_loss(epoch)
    val_loss = fake_loss(epoch, base=1.5, decay=0.15)
    train_acc = fake_accuracy(epoch)
    val_acc = fake_accuracy(epoch - 0.5)

    # Primary format: KVERITAS_METRIC — these are guaranteed to be captured.
    print(f"KVERITAS_METRIC name=train_loss value={train_loss:.6f} step={epoch}")
    print(f"KVERITAS_METRIC name=val_loss value={val_loss:.6f} step={epoch}")
    print(f"KVERITAS_METRIC name=train_accuracy value={train_acc:.6f} step={epoch}")
    print(f"KVERITAS_METRIC name=val_accuracy value={val_acc:.6f} step={epoch}")

    # Human-readable summary (also picked up by heuristic parser as a bonus).
    print(f"Epoch {epoch:02d}/{EPOCHS}  "
          f"loss: {train_loss:.4f} - val_loss: {val_loss:.4f} - "
          f"accuracy: {train_acc:.4f} - val_accuracy: {val_acc:.4f}")

print()
print("Training complete.")

final_val_acc = fake_accuracy(EPOCHS)
final_val_loss = fake_loss(EPOCHS, base=1.5, decay=0.15)

print(f"KVERITAS_METRIC name=final_val_accuracy value={final_val_acc:.6f} step=final")
print(f"KVERITAS_METRIC name=final_val_loss value={final_val_loss:.6f} step=final")
