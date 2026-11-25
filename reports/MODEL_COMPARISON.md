# CIC-IoT model comparison

Input: `data/processed/ciciot_flows.csv`

All candidates used identical feature columns and splits. The original candidates use inverse-frequency class weights. The family-weighted Histogram Gradient Boosting candidate additionally weights attack rows by inverse square-root family frequency, normalized to preserve the total attack weight. All weights use training rows.

Feasible validation points take priority, ranked by attack recall, lower achieved FPR, then tighter target. If every point is infeasible, validation F1 takes priority. Test evaluation follows selection. Medium thresholds are half the high threshold and indicate risk without an ML alert.

Selected algorithm: **HistGradientBoostingClassifier**

Train / validation / test flow counts: 71434 / 25403 / 25364.

PR-AUC uses trapezoidal integration. The confusion matrix gives true class by row and predicted class by column, ordered benign then attack. Latency is the median of 50 warm, single-row predict_proba calls on this host with one worker thread.

## Validation grid

| Candidate | FPR target | High threshold | Validation FPR | Validation recall | Feasible |
|---|---:|---:|---:|---:|---|
| RandomForestClassifier | 2.00% | 0.826000000 | 31.9879% | 76.7835% | No |
| HistGradientBoostingClassifier | 2.00% | 0.965876221 | 1.9997% | 54.9870% | Yes |
| Family-weighted HistGradientBoostingClassifier | 2.00% | 0.965667779 | 1.7923% | 53.9955% | Yes |

## Before and after

Before uses HistGradientBoostingClassifier with the original 3% validation FPR policy. After uses HistGradientBoostingClassifier at a 2.00% target.

| Operating point | Before | After |
|---|---:|---:|
| high_threshold | 0.959174746155 | 0.965876220564 |
| med_threshold | 0.479587373077 | 0.482938110282 |
| Validation recall | 0.559196706 | 0.549869759 |
| Validation fpr | 0.027625537 | 0.019997037 |
| Test accuracy | 0.754809967 | 0.752326132 |
| Test precision | 0.995772028 | 0.996575342 |
| Test recall | 0.487336534 | 0.481708326 |
| Test f1 | 0.654404001 | 0.649481085 |
| Test fpr | 0.001882247 | 0.001505797 |
| Test roc_auc | 0.919956534 | 0.919956534 |
| Test pr_auc | 0.929681628 | 0.929681628 |

| Test attack family | Recall before | Recall after |
|---|---:|---:|
| BruteForce | 0.039111111 | 0.037333333 |
| DDoS | 0.522935780 | 0.522935780 |
| DoS | 0.996888889 | 0.996888889 |
| Mirai | 0.000000000 | 0.000000000 |
| Recon | 0.748222222 | 0.736000000 |
| Spoofing | 0.020000000 | 0.020000000 |
| Web-based | 0.125894134 | 0.113018598 |

## Baseline test misses

The medium band includes its lower boundary and excludes the high threshold.

| Attack family | Missed | Below medium | Medium band | Min score | Median score | Max score |
|---|---:|---:|---:|---:|---:|---:|
| BruteForce | 2162 | 524 | 1638 | 0.097476465 | 0.633599160 | 0.958409043 |
| DDoS | 52 | 26 | 26 | 0.060886213 | 0.496908898 | 0.959092556 |
| DoS | 7 | 2 | 5 | 0.276952805 | 0.875255543 | 0.956450681 |
| Mirai | 24 | 12 | 12 | 0.138319980 | 0.446448146 | 0.896607771 |
| Recon | 1133 | 363 | 770 | 0.032043778 | 0.720585757 | 0.959138246 |
| Spoofing | 2205 | 1309 | 896 | 0.040938904 | 0.386260510 | 0.956498663 |
| Web-based | 611 | 182 | 429 | 0.133070093 | 0.711655609 | 0.958711317 |

## RandomForestClassifier

High threshold: 0.82599999999999996 (validation best F1 because no interior cutoff met FPR <= 2.00%). Medium threshold: 0.41299999999999998 (heuristic, half of high).

Validation F1: 0.7207. Validation FPR: 0.3199.

| Test metric | Value |
|---|---:|
| accuracy | 0.79388 |
| precision | 0.86280 |
| recall | 0.67456 |
| f1 | 0.75715 |
| fpr | 0.09758 |
| roc_auc | 0.87435 |
| pr_auc | 0.89356 |
| average_precision | 0.88818 |

Confusion matrix: `[[11986, 1296], [3932, 8150]]`

Serialized bundle: 81402.00 KiB. Warm inference: 19.7869 ms.

| Test attack family | Recall |
|---|---:|
| BruteForce | 0.28889 |
| DDoS | 0.70642 |
| DoS | 0.99956 |
| Mirai | 0.20833 |
| Recon | 0.89800 |
| Spoofing | 0.30044 |
| Web-based | 0.64664 |

## HistGradientBoostingClassifier

High threshold: 0.96587622056363209 (maximize validation recall subject to FPR <= 2.00%). Medium threshold: 0.48293811028181605 (heuristic, half of high).

Validation F1: 0.6993. Validation FPR: 0.0200.

| Test metric | Value |
|---|---:|
| accuracy | 0.75233 |
| precision | 0.99658 |
| recall | 0.48171 |
| f1 | 0.64948 |
| fpr | 0.00151 |
| roc_auc | 0.91996 |
| pr_auc | 0.92968 |
| average_precision | 0.92946 |

Confusion matrix: `[[13262, 20], [6262, 5820]]`

Serialized bundle: 712.57 KiB. Warm inference: 6.5555 ms.

| Test attack family | Recall |
|---|---:|
| BruteForce | 0.03733 |
| DDoS | 0.52294 |
| DoS | 0.99689 |
| Mirai | 0.00000 |
| Recon | 0.73600 |
| Spoofing | 0.02000 |
| Web-based | 0.11302 |

## Family-weighted HistGradientBoostingClassifier

High threshold: 0.96566777881847221 (maximize validation recall subject to FPR <= 2.00%). Medium threshold: 0.48283388940923611 (heuristic, half of high).

Validation F1: 0.6921. Validation FPR: 0.0179.

| Test metric | Value |
|---|---:|
| accuracy | 0.74819 |
| precision | 0.99530 |
| recall | 0.47360 |
| f1 | 0.64180 |
| fpr | 0.00203 |
| roc_auc | 0.92159 |
| pr_auc | 0.92978 |
| average_precision | 0.92956 |

Confusion matrix: `[[13255, 27], [6360, 5722]]`

Serialized bundle: 711.06 KiB. Warm inference: 5.6319 ms.

| Test attack family | Recall |
|---|---:|
| BruteForce | 0.03156 |
| DDoS | 0.53211 |
| DoS | 0.99644 |
| Mirai | 0.00000 |
| Recon | 0.72267 |
| Spoofing | 0.01022 |
| Web-based | 0.10873 |

