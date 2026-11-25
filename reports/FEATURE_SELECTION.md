# Flow feature selection

Input `ciciot_flows.csv`, SHA256 `b29c41f1ba9efdb5703c9c7af9df3afac2a58f6cf05fffaac0a6ea0238722191`.

## Split membership

Targets are 70% training, 15% validation and 15% test. Within each family, whole captures are assigned largest first to the partition furthest below target, reserving one file per partition. Explicit training captures are assigned first as whole files. Families with fewer than three captures use chronological blocks in each file. One flow immediately before each boundary and earlier flows ending at or after the next block are withheld. These blocks still share capture conditions, limiting generalization claims.

| source_pcap | attack_family | method | train | val | test | embargo |
| --- | --- | --- | --- | --- | --- | --- |
| BenignTraffic4.pcap | Benign | whole capture pinned to train | 1806 | 0 | 0 | 0 |
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

Each subset uses a 50-tree random forest with balanced training class weights and seed 42. The run requires the full 29-feature contract. D removes training constants and later contract-order features with absolute Pearson correlation ≥0.98 to an already retained feature. Validation and test retain their original class mix.

| subset | features | f1 | precision | recall |
| --- | --- | --- | --- | --- |
| A: all features | 29 | 0.71304 | 0.59964 | 0.87934 |
| B: volume and timing | 21 | 0.69391 | 0.57443 | 0.87614 |
| C: volume, timing and flags | 27 | 0.70015 | 0.58801 | 0.86514 |
| D: training EDA | 28 | 0.71554 | 0.60227 | 0.88127 |

Selected **A: all features**. Ordered inputs: PROTOCOL_NUM, IN_PKTS, OUT_PKTS, IN_BYTES, OUT_BYTES, FLOW_DURATION_MILLISECONDS, PKTS_PER_SEC, BYTES_PER_SEC, IN_OUT_PKT_RATIO, IN_OUT_BYTE_RATIO, PKT_LEN_MIN, PKT_LEN_MAX, PKT_LEN_MEAN, PKT_LEN_STD, TTL_MEAN, SYN_RATIO, ACK_RATIO, FIN_RATIO, RST_RATIO, PSH_RATIO, URG_RATIO, SRC_TO_DST_IAT_MIN, SRC_TO_DST_IAT_MAX, SRC_TO_DST_IAT_AVG, SRC_TO_DST_IAT_STDDEV, DST_TO_SRC_IAT_MIN, DST_TO_SRC_IAT_MAX, DST_TO_SRC_IAT_AVG, DST_TO_SRC_IAT_STDDEV.

## Validation permutation importance

Mean decrease in attack F1 over three permutations on 5,000 uniformly sampled validation flows (seed 42).

| feature | mean F1 decrease |
| --- | --- |
| SYN_RATIO | 0.096688 |
| PKT_LEN_MEAN | 0.019436 |
| TTL_MEAN | 0.018059 |
| PKT_LEN_MAX | 0.011132 |
| IN_OUT_BYTE_RATIO | 0.010861 |
| PKT_LEN_MIN | 0.010207 |
| IN_BYTES | 0.0092651 |
| FLOW_DURATION_MILLISECONDS | 0.0085027 |
| PKT_LEN_STD | 0.0083622 |
| IN_PKTS | 0.0065331 |
| ACK_RATIO | 0.0061415 |
| SRC_TO_DST_IAT_MIN | 0.0045127 |
| SRC_TO_DST_IAT_AVG | 0.0042748 |
| SRC_TO_DST_IAT_STDDEV | 0.0042288 |
| PROTOCOL_NUM | 0.004125 |
| OUT_BYTES | 0.0038953 |
| BYTES_PER_SEC | 0.0034999 |
| IN_OUT_PKT_RATIO | 0.0023518 |
| DST_TO_SRC_IAT_AVG | 0.0018495 |
| FIN_RATIO | 0.0015413 |
| SRC_TO_DST_IAT_MAX | 0.0011902 |
| RST_RATIO | 0.001009 |
| DST_TO_SRC_IAT_MIN | 0.00088297 |
| DST_TO_SRC_IAT_MAX | 0.00084623 |
| DST_TO_SRC_IAT_STDDEV | 0.00076391 |
| PKTS_PER_SEC | 0.00037742 |
| OUT_PKTS | 0.00026579 |
| URG_RATIO | 0 |
| PSH_RATIO | -0.00049117 |
