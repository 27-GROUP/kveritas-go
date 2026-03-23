"""
Experiment 1: MLP Classifier on synthetic dataset.
Simulates a 3-layer MLP trained on a 10-class classification task.
"""
import time
import math
import random

random.seed(7)

EPOCHS = 15
LEARNING_RATE = 3e-4
BATCH_SIZE = 64
HIDDEN_DIM = 512
NUM_CLASSES = 10
TRAIN_SAMPLES = 8000
VAL_SAMPLES = 2000

print(f"Experiment: MLP Classifier")
print(f"Architecture: Linear({HIDDEN_DIM}) -> ReLU -> Linear({HIDDEN_DIM//2}) -> ReLU -> Linear({NUM_CLASSES})")
print(f"Optimizer: AdamW(lr={LEARNING_RATE}, weight_decay=1e-4)")
print(f"Dataset: synthetic, {TRAIN_SAMPLES} train / {VAL_SAMPLES} val, {NUM_CLASSES} classes")
print(f"Batch size: {BATCH_SIZE}")
print()

def loss_curve(epoch, base=2.3, decay=0.21, noise_std=0.012):
    return base * math.exp(-decay * epoch) + random.gauss(0, noise_std)

def acc_curve(epoch, ceiling=0.961, warmup=0.52, rate=0.048, noise_std=0.004):
    return min(ceiling, warmup + rate * epoch + random.gauss(0, noise_std))

best_val_acc = 0.0
best_epoch = 0

for epoch in range(1, EPOCHS + 1):
    time.sleep(0.04)

    train_loss = loss_curve(epoch, base=2.3, decay=0.21)
    val_loss   = loss_curve(epoch, base=2.45, decay=0.18, noise_std=0.018)
    train_acc  = acc_curve(epoch, ceiling=0.972, warmup=0.50, rate=0.047)
    val_acc    = acc_curve(epoch, ceiling=0.961, warmup=0.48, rate=0.044)
    top5_acc   = min(0.998, val_acc + 0.029 + random.gauss(0, 0.002))

    if val_acc > best_val_acc:
        best_val_acc = val_acc
        best_epoch = epoch

    print(f"KVERITAS_METRIC name=train_loss value={train_loss:.6f} step={epoch}")
    print(f"KVERITAS_METRIC name=val_loss value={val_loss:.6f} step={epoch}")
    print(f"KVERITAS_METRIC name=train_accuracy value={train_acc:.6f} step={epoch}")
    print(f"KVERITAS_METRIC name=val_accuracy value={val_acc:.6f} step={epoch}")
    print(f"KVERITAS_METRIC name=val_top5_accuracy value={top5_acc:.6f} step={epoch}")

    print(f"Epoch {epoch:02d}/{EPOCHS}  "
          f"loss: {train_loss:.4f}  val_loss: {val_loss:.4f}  "
          f"acc: {train_acc:.4f}  val_acc: {val_acc:.4f}  top5: {top5_acc:.4f}")

print()
print(f"Training complete. Best val_accuracy={best_val_acc:.4f} at epoch {best_epoch}.")
print()
print(f"KVERITAS_METRIC name=best_val_accuracy value={best_val_acc:.6f} step=final")
print(f"KVERITAS_METRIC name=best_epoch value={float(best_epoch):.1f} step=final")
