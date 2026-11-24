# Flow feature selection

Input `ciciot_flows.csv`, SHA256 `3d68bb16c1a1ed946be92adb4f3f62ff64b4db374e89a0668410c94e9786b9af`.

## Split membership

Targets are 70% training, 15% validation and 15% test. Within each family, whole captures are assigned largest first to the partition furthest below target, reserving one file per partition. Families with fewer than three captures use chronological blocks in each file. One flow immediately before each boundary and earlier flows ending at or after the next block are withheld. These blocks still share capture conditions, limiting generalization claims.

| source_pcap | attack_family | method | train | val | test | embargo |
| --- | --- | --- | --- | --- | --- | --- |
| BenignTraffic2.pcap | Benign | whole capture | 13621 | 0 | 0 | 0 |
| BenignTraffic3.pcap | Benign | whole capture | 0 | 13502 | 0 | 0 |
| BenignTraffic1.pcap | Benign | whole capture | 0 | 0 | 13282 | 0 |
| DictionaryBruteForce.pcap | BruteForce | chronological with embargo | 10467 | 2214 | 2250 | 69 |
| DDoS-UDP_Flood20.pcap | DDoS | chronological with embargo | 293 | 56 | 72 | 58 |
| DDoS-ICMP_Flood.pcap | DDoS | chronological with embargo | 111 | 30 | 37 | 65 |
| DoS-SYN_Flood7.pcap | DoS | chronological with embargo | 10475 | 2205 | 2250 | 70 |
| Mirai-udpplain24.pcap | Mirai | chronological with embargo | 83 | 13 | 24 | 34 |
| Recon-OSScan.pcap | Recon | chronological with embargo | 10435 | 2239 | 2250 | 76 |
| Recon-PortScan.pcap | Recon | chronological with embargo | 10464 | 2247 | 2250 | 39 |
| DNS_Spoofing.pcap | Spoofing | chronological with embargo | 10459 | 2238 | 2250 | 53 |
| Backdoor_Malware.pcap | Web-based | chronological with embargo | 3220 | 659 | 699 | 76 |

## Validation comparison

Each subset uses a 50-tree random forest with balanced training class weights and seed 42. The highest validation attack F1 wins. Ties favor fewer features, then the first listed subset. D removes training constants and later contract-order features with absolute Pearson correlation ≥0.98 to an already retained feature. Validation and test retain their original class mix.

| subset | features | f1 | precision | recall |
| --- | --- | --- | --- | --- |
| A: all features | 29 | 0.715 | 0.60054 | 0.88337 |
| B: volume and timing | 21 | 0.69412 | 0.57479 | 0.87598 |
| C: volume, timing and flags | 27 | 0.70289 | 0.59544 | 0.85766 |
| D: training EDA | 29 | 0.715 | 0.60054 | 0.88337 |

Selected **A: all features**. Ordered inputs: PROTOCOL_NUM, IN_PKTS, OUT_PKTS, IN_BYTES, OUT_BYTES, FLOW_DURATION_MILLISECONDS, PKTS_PER_SEC, BYTES_PER_SEC, IN_OUT_PKT_RATIO, IN_OUT_BYTE_RATIO, PKT_LEN_MIN, PKT_LEN_MAX, PKT_LEN_MEAN, PKT_LEN_STD, TTL_MEAN, SYN_RATIO, ACK_RATIO, FIN_RATIO, RST_RATIO, PSH_RATIO, URG_RATIO, SRC_TO_DST_IAT_MIN, SRC_TO_DST_IAT_MAX, SRC_TO_DST_IAT_AVG, SRC_TO_DST_IAT_STDDEV, DST_TO_SRC_IAT_MIN, DST_TO_SRC_IAT_MAX, DST_TO_SRC_IAT_AVG, DST_TO_SRC_IAT_STDDEV.

## Validation permutation importance

Mean decrease in attack F1 over three permutations on 5,000 uniformly sampled validation flows (seed 42).

| feature | mean F1 decrease |
| --- | --- |
| TTL_MEAN | 0.02311 |
| IN_BYTES | 0.020292 |
| PKT_LEN_MEAN | 0.017937 |
| SYN_RATIO | 0.017679 |
| PKTS_PER_SEC | 0.01506 |
| PKT_LEN_MAX | 0.0142 |
| FLOW_DURATION_MILLISECONDS | 0.01144 |
| PKT_LEN_STD | 0.010841 |
| SRC_TO_DST_IAT_AVG | 0.01016 |
| PKT_LEN_MIN | 0.0097248 |
| IN_OUT_BYTE_RATIO | 0.0095436 |
| BYTES_PER_SEC | 0.008917 |
| RST_RATIO | 0.0084454 |
| OUT_BYTES | 0.0072161 |
| SRC_TO_DST_IAT_MAX | 0.0063119 |
| ACK_RATIO | 0.0059627 |
| SRC_TO_DST_IAT_MIN | 0.0050814 |
| SRC_TO_DST_IAT_STDDEV | 0.0047014 |
| PROTOCOL_NUM | 0.0046316 |
| IN_OUT_PKT_RATIO | 0.0036997 |
| FIN_RATIO | 0.003166 |
| DST_TO_SRC_IAT_MAX | 0.0018791 |
| PSH_RATIO | 0.0018096 |
| IN_PKTS | 0.0016384 |
| DST_TO_SRC_IAT_STDDEV | 0.0014071 |
| DST_TO_SRC_IAT_MIN | 0.0012347 |
| DST_TO_SRC_IAT_AVG | 0.00091135 |
| OUT_PKTS | 0.00067517 |
| URG_RATIO | 0 |
