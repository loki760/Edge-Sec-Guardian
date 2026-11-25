# Physical Pi 5 inline browsing comparison

Headless Chrome used the Pi as an Ethernet gateway for the same multi-site schedule in both runs. The workload included three YouTube video plays, public news and developer sites, and a 20-second idle wait after the browser closed. Public-site traffic and background flows varied across runs. Browser evidence confirmed HTTP/3, HTTP/2 and WebSocket handshakes.

| Recorded measurement | Before fixes | After fixes |
| --- | ---: | ---: |
| Monitor elapsed (s) | 180.23 | 180.46 |
| Packets seen | 118,819 | 202,258 |
| Kernel packets dropped | 124,293 | 0 |
| Completed flow queue drops | Unmeasured | 0 |
| Emitted flows | 3,766 | 5,492 |
| Flows recovered in API snapshots | 3,697 | 5,016 |
| Scored / unscored recovered flows | 3,691 / 6 | 4,727 / 289 |
| High alert rows | 464 | 13 |
| High alerts involving a rule | 424 | 0 |
| High alerts from ML alone | 40 | 13 |
| Clear flows in the Medium score band | 620 | 515 |
| Chrome HTTP/3 responses | 1,005 | 1,015 |

The first run contained 422 TCP port-burst alerts on gateway DNS response flows and two rate-only alerts on bidirectional HTTPS. The 422 include one alert that also had an ML signal. In the rerun, 282 recovered flows were excluded as isolated TCP replies. All 13 High alerts were ML-only TCP/443 flows. Ten were two-packet flows with a SYN and SYN-ACK followed by idle timeout. These may be preconnects or abandoned handshakes. The browser endpoint records did not attribute the 13 flows to test sites. The rerun High-alert share is 13 / 4,727 = 0.275% among recovered scored flows. A labeled live false-positive rate is unavailable.

## Offline scan fixture and local explanation

The final on-device fixture submitted 80 in-memory TCP connection-attempt records to the detector. The detector raised 72 High port-burst alerts in a temporary database. The physical Pi's ExecuTorch worker completed two invocations with zero errors. These records exercised the detector and explanation path without sending traffic.

## Evidence retained locally

The raw files below remain under `artifacts/` in the working copy. They include endpoints and per-flow records, so only aggregates are tracked in this report.

| Local evidence file | SHA-256 |
| --- | --- |
| `benchmark_benign_browser.json` | `cb12e3708055fcd7119bde5a59cf076b8657e5437a363714a11158f1541c090` |
| `benchmark_benign_findings.json` | `72f817f2cc66a4e78487d644612701d44104b32e0dfcd977b7a6a6740e2ab24a` |
| `benchmark_benign_live.json` | `715715822c29eff038e63f949dae1fb0023a88b62736782072dc1df7b6ab9293` |
| `benchmark_benign_browser_rerun.json` | `b1dae67e0e736deb23c76d88ab4c0b7342ee9d334db4a5b53699f9464cdef648` |
| `benchmark_benign_findings_rerun.json` | `6290ef79063007ffd422cc1dfc65e1ab4ce33bedbb9f97156b30108357a3fc8b` |
| `benchmark_benign_live_rerun.json` | `310d5a7ebe8f530cd68d856e9cd7722723bc1e6e48f9632c4d5415e082a2fb1c` |
| `benchmark_scan_offline_rerun.log` | `c195255553fd0151bf53a86c7a9d11403f5724eca9d2597a2f75adeec45b0c8` |
