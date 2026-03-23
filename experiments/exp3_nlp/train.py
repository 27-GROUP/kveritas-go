"""
Experiment 3: Transformer fine-tuning for text classification.
Simulates fine-tuning a BERT-sized model on a sentiment analysis task.
"""
import time
import math
import random

random.seed(99)

EPOCHS = 5
LEARNING_RATE = 2e-5
WARMUP_STEPS = 500
MAX_SEQ_LEN = 128
BATCH_SIZE = 32
TRAIN_SAMPLES = 25000
VAL_SAMPLES = 5000

print(f"Experiment: Transformer Text Classification (Sentiment)")
print(f"Model: BERT-base-uncased (110M parameters)")
print(f"Task: SST-2 binary sentiment classification")
print(f"LR: {LEARNING_RATE}  warmup: {WARMUP_STEPS}  max_seq_len: {MAX_SEQ_LEN}")
print(f"Dataset: {TRAIN_SAMPLES} train / {VAL_SAMPLES} val")
print()

steps_per_epoch = TRAIN_SAMPLES // BATCH_SIZE

def transformer_loss(step, base=0.692, decay=0.00085, noise_std=0.008):
    return max(0.08, base * math.exp(-decay * step) + random.gauss(0, noise_std))

def transformer_acc(step, ceiling=0.9421, rate=0.000095, noise_std=0.003):
    return min(ceiling, 0.510 + rate * step + random.gauss(0, noise_std))

global_step = 0
for epoch in range(1, EPOCHS + 1):
    epoch_losses = []
    for batch in range(0, steps_per_epoch, steps_per_epoch // 6):
        global_step += steps_per_epoch // 6
        time.sleep(0.02)
        loss = transformer_loss(global_step)
        epoch_losses.append(loss)
        print(f"Epoch {epoch} step {global_step:5d}/{EPOCHS*steps_per_epoch}  loss={loss:.4f}")
        print(f"KVERITAS_METRIC name=train_loss value={loss:.6f} step={global_step}")

    val_loss = transformer_loss(global_step, base=0.71, decay=0.00080, noise_std=0.009)
    val_acc  = transformer_acc(global_step)
    val_mcc  = 2 * val_acc - 1.0 + random.gauss(0, 0.004)

    print(f"--- Epoch {epoch} eval  val_loss={val_loss:.4f}  val_acc={val_acc:.4f}  matthews={val_mcc:.4f}")
    print(f"KVERITAS_METRIC name=val_loss value={val_loss:.6f} step={epoch}")
    print(f"KVERITAS_METRIC name=val_accuracy value={val_acc:.6f} step={epoch}")
    print(f"KVERITAS_METRIC name=matthews_corr value={val_mcc:.6f} step={epoch}")
    print()

final_val_acc = transformer_acc(global_step)
final_val_mcc = 2 * final_val_acc - 1.0 + random.gauss(0, 0.002)

print("Training complete.")
print(f"KVERITAS_METRIC name=final_val_accuracy value={final_val_acc:.6f} step=final")
print(f"KVERITAS_METRIC name=final_matthews_corr value={final_val_mcc:.6f} step=final")
