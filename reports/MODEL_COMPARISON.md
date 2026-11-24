# CIC-IoT model comparison

Input: `data/processed/ciciot_flows.csv`

All candidates used identical feature columns and splits. The original candidates use inverse-frequency class weights. The family-weighted Histogram Gradient Boosting candidate additionally weights attack rows by inverse square-root family frequency, normalized to preserve the total attack weight. All weights use training rows.

Feasible validation points take priority, ranked by attack recall, lower achieved FPR, then tighter target. If every point is infeasible, validation F1 takes priority. Test evaluation follows selection. Medium thresholds are half the high threshold and indicate risk without an ML alert.

Selected algorithm: **HistGradientBoostingClassifier**

Train / validation / test flow counts: 69628 / 25403 / 25364.

PR-AUC uses trapezoidal integration. The confusion matrix gives true class by row and predicted class by column, ordered benign then attack. Latency is the median of 50 warm, single-row predict_proba calls on this host with one worker thread.

## Validation grid

| Candidate | FPR target | High threshold | Validation FPR | Validation recall | Feasible |
|---|---:|---:|---:|---:|---|
| RandomForestClassifier | 1.50% | 0.732142857 | 40.1200% | 82.4300% | No |
| RandomForestClassifier | 2.00% | 0.732142857 | 40.1200% | 82.4300% | No |
| RandomForestClassifier | 2.50% | 0.732142857 | 40.1200% | 82.4300% | No |
| HistGradientBoostingClassifier | 1.50% | 0.992663786 | 1.4961% | 51.6091% | Yes |
| HistGradientBoostingClassifier | 2.00% | 0.960418918 | 1.7701% | 55.8188% | Yes |
| HistGradientBoostingClassifier | 2.50% | 0.960418918 | 1.7701% | 55.8188% | Yes |
| Family-weighted HistGradientBoostingClassifier | 1.50% | 0.992544399 | 1.4739% | 52.0881% | Yes |
| Family-weighted HistGradientBoostingClassifier | 2.00% | 0.972480731 | 1.7627% | 53.6594% | Yes |
| Family-weighted HistGradientBoostingClassifier | 2.50% | 0.972480731 | 1.7627% | 53.6594% | Yes |

## Before and after

Before uses HistGradientBoostingClassifier with the original 3% validation FPR policy. After uses HistGradientBoostingClassifier at a 2.00% target.

| Operating point | Before | After |
|---|---:|---:|
| high_threshold | 0.953008027720 | 0.960418917768 |
| med_threshold | 0.476504013860 | 0.480209458884 |
| Validation recall | 0.564910512 | 0.558188388 |
| Validation fpr | 0.026588654 | 0.017701081 |
| Test accuracy | 0.761591232 | 0.758279451 |
| Test precision | 0.996217727 | 0.997492058 |
| Test recall | 0.501407052 | 0.493792418 |
| Test f1 | 0.667070418 | 0.660576870 |
| Test fpr | 0.001731667 | 0.001129348 |
| Test roc_auc | 0.922517275 | 0.922517275 |
| Test pr_auc | 0.930415056 | 0.930415056 |

| Test attack family | Recall before | Recall after |
|---|---:|---:|
| BruteForce | 0.061777778 | 0.042666667 |
| DDoS | 0.559633028 | 0.532110092 |
| DoS | 0.997777778 | 0.997777778 |
| Mirai | 0.000000000 | 0.000000000 |
| Recon | 0.766000000 | 0.760444444 |
| Spoofing | 0.032444444 | 0.028444444 |
| Web-based | 0.133047210 | 0.115879828 |

## Baseline test misses

The medium band includes its lower boundary and excludes the high threshold.

| Attack family | Missed | Below medium | Medium band | Min score | Median score | Max score |
|---|---:|---:|---:|---:|---:|---:|
| BruteForce | 2111 | 475 | 1636 | 0.083451101 | 0.685984610 | 0.952628678 |
| DDoS | 48 | 23 | 25 | 0.069583330 | 0.530718133 | 0.946233528 |
| DoS | 5 | 1 | 4 | 0.270625109 | 0.840647785 | 0.928425044 |
| Mirai | 24 | 9 | 15 | 0.077675855 | 0.661783973 | 0.952184713 |
| Recon | 1053 | 377 | 676 | 0.039154077 | 0.687704681 | 0.952978019 |
| Spoofing | 2177 | 1301 | 876 | 0.028202400 | 0.369935829 | 0.950231153 |
| Web-based | 606 | 194 | 412 | 0.102654871 | 0.698330355 | 0.952713085 |

## RandomForestClassifier

High threshold: 0.73214285714285721 (validation best F1 because no interior cutoff met FPR <= 1.50%). Medium threshold: 0.3660714285714286 (heuristic, half of high).

Validation F1: 0.7232. Validation FPR: 0.4012.

| Test metric | Value |
|---|---:|
| accuracy | 0.80898 |
| precision | 0.81594 |
| recall | 0.77346 |
| f1 | 0.79414 |
| fpr | 0.15871 |
| roc_auc | 0.87721 |
| pr_auc | 0.89705 |
| average_precision | 0.89187 |

Confusion matrix: `[[11174, 2108], [2737, 9345]]`

Serialized bundle: 78823.67 KiB. Warm inference: 5.2883 ms.

| Test attack family | Recall |
|---|---:|
| BruteForce | 0.64089 |
| DDoS | 0.77982 |
| DoS | 1.00000 |
| Mirai | 0.37500 |
| Recon | 0.92067 |
| Spoofing | 0.39689 |
| Web-based | 0.74821 |

## HistGradientBoostingClassifier

High threshold: 0.9604189177676925 (maximize validation recall subject to FPR <= 2.00%). Medium threshold: 0.48020945888384625 (heuristic, half of high).

Validation F1: 0.7073. Validation FPR: 0.0177.

| Test metric | Value |
|---|---:|
| accuracy | 0.75828 |
| precision | 0.99749 |
| recall | 0.49379 |
| f1 | 0.66058 |
| fpr | 0.00113 |
| roc_auc | 0.92252 |
| pr_auc | 0.93042 |
| average_precision | 0.93019 |

Confusion matrix: `[[13267, 15], [6116, 5966]]`

Serialized bundle: 712.79 KiB. Warm inference: 1.6791 ms.

| Test attack family | Recall |
|---|---:|
| BruteForce | 0.04267 |
| DDoS | 0.53211 |
| DoS | 0.99778 |
| Mirai | 0.00000 |
| Recon | 0.76044 |
| Spoofing | 0.02844 |
| Web-based | 0.11588 |

## Family-weighted HistGradientBoostingClassifier

High threshold: 0.97248073078094188 (maximize validation recall subject to FPR <= 2.00%). Medium threshold: 0.48624036539047094 (heuristic, half of high).

Validation F1: 0.6894. Validation FPR: 0.0176.

| Test metric | Value |
|---|---:|
| accuracy | 0.74239 |
| precision | 0.99695 |
| recall | 0.46060 |
| f1 | 0.63010 |
| fpr | 0.00128 |
| roc_auc | 0.92205 |
| pr_auc | 0.93083 |
| average_precision | 0.93061 |

Confusion matrix: `[[13265, 17], [6517, 5565]]`

Serialized bundle: 714.37 KiB. Warm inference: 1.7119 ms.

| Test attack family | Recall |
|---|---:|
| BruteForce | 0.03022 |
| DDoS | 0.56881 |
| DoS | 0.99733 |
| Mirai | 0.08333 |
| Recon | 0.68889 |
| Spoofing | 0.01111 |
| Web-based | 0.09156 |

