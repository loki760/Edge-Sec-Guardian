# Edge-Sec-Guardian: Stages 1–2

Offline IPv4 TCP/UDP packet analysis for a Raspberry Pi 5. Scapy reads a PCAP,
packets are grouped into bidirectional flows, and each flow becomes one CSV row
with five identification columns and 16 numerical features. Scapy is the only
third-party dependency. Use Python 3.9 or newer. Developers can use either the
virtual environment below or the optional Docker setup.

## Docker development (Raspberry Pi 5 / ARM64)

The Dockerfile uses Python 3.13 on Debian Trixie, matching the Pi's tested
Python major/minor version and distribution. It supports 64-bit Raspberry Pi OS
on Pi 5, Apple Silicon Macs, and other Docker hosts. This is a project container,
not a bootable Raspberry Pi OS image or hardware emulator: containers use the
Docker host's Linux kernel. It covers offline PCAP analysis only.

Install [Docker Desktop](https://docs.docker.com/desktop/) on a Mac/Windows
development machine, or [Docker Engine for Debian](https://docs.docker.com/engine/install/debian/)
on a Pi running 64-bit Raspberry Pi OS/Debian. Start Docker before building.
On Linux, the commands assume your user can access Docker; otherwise use `sudo`
for Docker commands. A working, writable host filesystem is required.

Clone and build the Pi-compatible ARM64 image:

```sh
git clone https://github.com/loki760/Edge-Sec-Guardian.git
cd Edge-Sec-Guardian
docker build --platform linux/arm64 -t edge-sec-guardian:dev .
```

If you already have the repository, use its existing folder instead of cloning.
The build downloads the Python base image and Scapy. Run all 16 tests:

```sh
docker run --rm --platform linux/arm64 edge-sec-guardian:dev python -m unittest -v
```

Run the sample pipeline and save the CSV in your host's `data/` directory
(Mac/Linux shell commands):

```sh
docker run --rm --platform linux/arm64 \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$(pwd)/data,target=/app/data" \
  edge-sec-guardian:dev
```

Expect 6 packets, 0 skipped, 3 flows, and `data/features.csv` on the host.
The mount keeps output after the container exits; `--user` gives new files your
host user's ownership. Existing output files must be writable by that user.
The default image user has UID 1000. No privileged mode, host networking, or
network capture capabilities are required for these offline commands.

To analyze your own capture, put it in `data/` and override the default command:

```sh
docker run --rm --platform linux/arm64 \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$(pwd)/data,target=/app/data" \
  edge-sec-guardian:dev \
  python extract_features.py --input data/my_capture.pcap --output data/my_features.csv
```

For editing code without rebuilding, mount the repository over `/app`:

```sh
docker run --rm -it --platform linux/arm64 \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$(pwd),target=/app" \
  edge-sec-guardian:dev sh
```

Inside, run `python -m unittest -v`, `python make_sample_pcap.py`, or the extractor.
Rebuild after changing `requirements.txt`. On Intel/AMD laptops, Docker Desktop
can emulate ARM64, which may be slower. For native x86 development, replace
`linux/arm64` with `linux/amd64` in both the build and run commands. See
[Docker's multi-platform guide](https://docs.docker.com/build/building/multi-platform/).

The `.dockerignore` includes only the scripts, requirements, and supplied sample
data in the build context. Virtual environments, Git history, credentials, and
other local captures are excluded. Additional captures remain accessible through
the explicit bind mount.

Verified on 14 November 2026 using Docker Desktop on the ARM64 Mac: image build,
all 16 tests, sample generation/extraction, host CSV output, and repository-mounted
execution passed. The image ran Python 3.13.18 on aarch64. Runtime checks passed
with networking disabled. This container has not yet been run on the physical Pi;
its previously observed read-only SD filesystem still needs resolution before
installing Docker or storing project files there.

## Raspberry Pi setup

From the Mac, connect using normal SSH authentication:

```sh
ssh shlok@192.168.2.2
```

On the Pi, inspect the existing environment first:

```sh
cat /etc/os-release
uname -m
python3 --version
python3 -m pip --version
git --version
free -h
df -h ~
mkdir -p ~/edge-sec-guardian
exit
```

Copy the project from the Mac (run from this repository's directory):

```sh
scp README.md requirements.txt .gitignore extract_features.py make_sample_pcap.py test_extract.py shlok@192.168.2.2:~/edge-sec-guardian/
ssh shlok@192.168.2.2
cd ~/edge-sec-guardian
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -c "import sys, scapy; print(sys.version); print('Scapy', scapy.__version__)"
```

If `venv` creation reports that `ensurepip` is unavailable, and the OS check
confirms Raspberry Pi OS/Debian/Ubuntu, install only the missing venv package:

```sh
sudo apt-get update
sudo apt-get install python3-venv
```

Then repeat venv creation, activation, and installation. The venv supplies pip;
system pip and Git are not required to run this program. If Python itself is
missing on that OS family, install `python3` and `python3-venv` first. Do not
run the extractor or pip with `sudo`.

## Run

Every new Pi terminal session needs activation:

```sh
cd ~/edge-sec-guardian
source .venv/bin/activate
python make_sample_pcap.py
python -m unittest -v
python extract_features.py --input data/sample.pcap --output data/features.csv
```

The sample generator writes six deterministic packets into three flows. The
extractor prints packet/skip counts, flow counts, and up to three flow summaries.
The output directory is created if needed. A valid empty capture produces a CSV
header with no rows. Missing files, empty files (without a PCAP header), and
unrecognized capture formats produce a short error and a nonzero exit status.

Tests use temporary files and check parsing, reverse grouping, counts, rates,
all feature calculations, flags, port counts, singleton/zero-duration flows,
timestamp ordering, unsupported/malformed packets, and CLI input/output.

For the sample TCP flow from port 5000 to port 80, expect 2 forward packets,
1 backward packet, 112 forward bytes, 54 backward bytes, 2 seconds duration,
1.5 packets/second, and 83 bytes/second. Its SYN/RST/ACK ratios are 2/3, 1/3,
and 2/3. The forward source has 3 distinct destination ports across the capture.

## Feature definitions

Forward is the first supported packet's source endpoint; backward is the reverse.
CSV identifiers (`source_ip`, `destination_ip`, `source_port`, `destination_port`,
`protocol`) use that first packet. TCP and UDP always form separate flows.
Repeated connections with the same five-tuple are combined across the whole
capture; this stage has no timeout or connection splitting.

Packet length is `len(packet)`: captured bytes including the available link-layer
header and payload. For Ethernet captures this normally excludes the FCS, preamble,
and inter-frame gap. Other capture link types may have different headers. This is
captured length, not the PCAP record's original on-wire length; incomplete IPv4
datagrams are skipped. Compare features from captures using the same link type.

| Feature | Definition and units |
| --- | --- |
| `flow_duration` | Latest minus earliest timestamp, seconds. |
| `total_fwd_pkts` | Number of forward packets. |
| `total_bwd_pkts` | Number of backward packets. |
| `total_fwd_bytes` | Sum of forward packet lengths, bytes. |
| `total_bwd_bytes` | Sum of backward packet lengths, bytes. |
| `pkt_rate` | All flow packets divided by duration, packets/second. |
| `byte_rate` | All flow bytes divided by duration, bytes/second. |
| `pkt_len_mean` | Mean of all flow packet lengths, bytes. |
| `pkt_len_std` | Population standard deviation of packet lengths, bytes. |
| `pkt_len_max` | Largest packet length, bytes. |
| `iat_mean` | Mean gap between consecutive chronologically sorted flow timestamps, seconds. |
| `iat_std` | Population standard deviation of those gaps, seconds. |
| `syn_ratio` | Packets with TCP SYN set divided by all flow packets. |
| `rst_ratio` | Packets with TCP RST set divided by all flow packets. |
| `ack_ratio` | Packets with TCP ACK set divided by all flow packets. |
| `unique_dst_ports_by_src` | Distinct destination port numbers contacted by this flow's forward source IP across all supported packets in the PCAP, including packets that are backward in other flows; TCP/UDP port numbers share one set. |

Rates are zero when duration is zero. A single-packet flow has zero duration,
packet-length standard deviation, and IAT statistics. One IAT has zero standard
deviation. UDP and missing TCP flags contribute no flags; combined TCP flags can
contribute to several ratios. All ratios are unitless. Chronological sorting affects
timing calculations only; first capture order still determines forward direction.

IPv6, non-TCP/UDP traffic, fragmented IPv4 packets (including first fragments),
and unsupported or malformed packet headers are skipped and counted. There is no
fragment reassembly or checksum validation. Port counts exclude skipped packets.
Packets stay in ordinary dictionaries/lists for the whole capture.

## Scope and verification

Implemented: offline parsing, bidirectional grouping, the 16 features, CSV export,
a small Scapy sample generator, and unittest checks. Future stages can add model
training and live analysis; neither is included here.

Verified on the Raspberry Pi on 11 November 2026: Debian 13 (trixie), aarch64,
Python 3.13.5, Scapy 2.6.1, Git 2.47.3, about 7 GiB available RAM and 100 GB
free disk space. All 16 unittest cases passed. The complete sample pipeline
processed 6 packets, skipped 0, found 3 flows, and saved a CSV with all 16
features. `pip check` reported no broken requirements. Pi-generated
`data/sample.pcap` and `data/features.csv` were copied back to this repository.

**Permanent Stage 1 setup is blocked by the Pi's storage condition.** The kernel
reported SD-card I/O errors and remounted the root filesystem read-only
(`emergency_ro`). Creating `~/edge-sec-guardian` failed. No remount, filesystem
repair, reboot, or system configuration change was attempted.

Verification instead used a virtual environment in the Pi's writable RAM:
`/tmp/edge-sec-guardian.4AwGiM/.venv`. The Pi's online pip installation failed,
so the Scapy 2.6.1 wheel was downloaded on the Mac, copied to that directory,
and installed with `pip --no-index`. Only Scapy was installed in the venv.

Until this temporary directory is removed or the Pi reboots, rerun on the Pi:

```sh
cd /tmp/edge-sec-guardian.4AwGiM
source .venv/bin/activate
python -m unittest -v
python extract_features.py --input data/sample.pcap --output data/features.csv
```

Resolve the storage problem before completing the permanent setup under
`~/edge-sec-guardian`; the temporary environment does not survive reboot.
