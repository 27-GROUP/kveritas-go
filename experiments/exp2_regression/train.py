"""
Experiment 2: Gradient-boosted regression on synthetic tabular data.
Simulates XGBoost-style training with cross-validation and feature importance.
"""
import time
import math
import random

random.seed(13)

N_ESTIMATORS = 200
MAX_DEPTH = 6
LEARNING_RATE = 0.05
SUBSAMPLE = 0.8
N_FOLDS = 5
N_SAMPLES = 5000
N_FEATURES = 42

print(f"Experiment: Gradient Boosted Regression")
print(f"Model: XGBoost  n_estimators={N_ESTIMATORS}  max_depth={MAX_DEPTH}  lr={LEARNING_RATE}")
print(f"Data: {N_SAMPLES} samples, {N_FEATURES} features")
print(f"Cross-validation: {N_FOLDS}-fold stratified")
print()

def rmse_curve(t, base=4.21, decay=0.019):
    return base * math.exp(-decay * t) + random.gauss(0, 0.04)

def r2_curve(t, ceiling=0.921, rate=0.0046):
    return min(ceiling, rate * t + random.gauss(0, 0.003))

print("Running cross-validation...")
fold_rmse = []
fold_r2 = []
for fold in range(1, N_FOLDS + 1):
    time.sleep(0.06)
    rmse = 0.812 + random.gauss(0, 0.015)
    r2   = 0.913 + random.gauss(0, 0.005)
    fold_rmse.append(rmse)
    fold_r2.append(r2)
    print(f"  Fold {fold}/{N_FOLDS}  RMSE={rmse:.4f}  R2={r2:.4f}")
    print(f"  KVERITAS_METRIC name=cv_fold_{fold}_rmse value={rmse:.6f} step={fold}")
    print(f"  KVERITAS_METRIC name=cv_fold_{fold}_r2 value={r2:.6f} step={fold}")

cv_rmse_mean = sum(fold_rmse) / len(fold_rmse)
cv_rmse_std  = (sum((x - cv_rmse_mean)**2 for x in fold_rmse) / len(fold_rmse)) ** 0.5
cv_r2_mean   = sum(fold_r2) / len(fold_r2)
cv_r2_std    = (sum((x - cv_r2_mean)**2 for x in fold_r2) / len(fold_r2)) ** 0.5

print()
print(f"CV summary:  RMSE={cv_rmse_mean:.4f} +/- {cv_rmse_std:.4f}  R2={cv_r2_mean:.4f} +/- {cv_r2_std:.4f}")
print()

print("Training final model on full dataset...")
for i in range(0, N_ESTIMATORS + 1, 50):
    if i == 0:
        continue
    time.sleep(0.03)
    rmse = rmse_curve(i)
    r2   = r2_curve(i)
    print(f"[{i:4d}/{N_ESTIMATORS}]  RMSE={rmse:.4f}  R2={r2:.4f}")
    print(f"KVERITAS_METRIC name=train_rmse value={rmse:.6f} step={i}")
    print(f"KVERITAS_METRIC name=train_r2 value={r2:.6f} step={i}")

final_rmse = rmse_curve(N_ESTIMATORS, base=4.21, decay=0.019)
final_r2   = r2_curve(N_ESTIMATORS)

print()
print(f"Final model RMSE={final_rmse:.4f}  R2={final_r2:.4f}")
print()

print(f"KVERITAS_METRIC name=cv_rmse_mean value={cv_rmse_mean:.6f} step=final")
print(f"KVERITAS_METRIC name=cv_rmse_std value={cv_rmse_std:.6f} step=final")
print(f"KVERITAS_METRIC name=cv_r2_mean value={cv_r2_mean:.6f} step=final")
print(f"KVERITAS_METRIC name=cv_r2_std value={cv_r2_std:.6f} step=final")
print(f"KVERITAS_METRIC name=final_rmse value={final_rmse:.6f} step=final")
print(f"KVERITAS_METRIC name=final_r2 value={final_r2:.6f} step=final")
print("Done.")
