# CIC-IoT model comparison

Input: `data/processed/ciciot_flows.csv`

Both models used identical feature columns and splits, with inverse-frequency sample weights on training rows only. Each model used its own validation cutoff. Models meeting the 3% validation FPR target took priority. Among equally feasible models, validation F1 determined the winner, with lower FPR breaking ties and Random Forest winning an exact tie. Test rows were evaluated after model selection.

Selected algorithm: **HistGradientBoostingClassifier**

Train / validation / test flow counts: 69628 / 25403 / 25364.

PR-AUC uses trapezoidal integration. The confusion matrix gives true class by row and predicted class by column, ordered benign then attack. Latency is the median of 50 warm, single-row predict_proba calls on this host with one worker thread.

## RandomForestClassifier

High threshold: 0.73214285714285721 (validation best F1 because no interior cutoff met FPR <= 3%). Medium threshold: 0.3660714285714286 (heuristic, half of high).

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

Serialized bundle: 78823.63 KiB. Warm inference: 18.9777 ms.

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

High threshold: 0.95300802771970472 (maximize validation F1 subject to FPR <= 3%). Medium threshold: 0.47650401385985236 (heuristic, half of high).

Validation F1: 0.7083. Validation FPR: 0.0266.

| Test metric | Value |
|---|---:|
| accuracy | 0.76159 |
| precision | 0.99622 |
| recall | 0.50141 |
| f1 | 0.66707 |
| fpr | 0.00173 |
| roc_auc | 0.92252 |
| pr_auc | 0.93042 |
| average_precision | 0.93019 |

Confusion matrix: `[[13259, 23], [6024, 6058]]`

Serialized bundle: 712.75 KiB. Warm inference: 6.8629 ms.

| Test attack family | Recall |
|---|---:|
| BruteForce | 0.06178 |
| DDoS | 0.55963 |
| DoS | 0.99778 |
| Mirai | 0.00000 |
| Recon | 0.76600 |
| Spoofing | 0.03244 |
| Web-based | 0.13305 |

