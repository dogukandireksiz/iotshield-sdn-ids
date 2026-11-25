# Mininet + Ryu test (Faz 7)

Goal: train on ASEADOS-SDN-IoT, test on our own SDN traffic, and measure the drop (domain shift).

## Environment

Three separate environments. None of them is the main `.venv`.

| What | Where | Versions |
| --- | --- | --- |
| Mininet, Open vSwitch, `hping3`, `nmap`, `tcpdump`, `ethtool` | system (Ubuntu VM), `sudo apt install ...` | from apt |
| Ryu controller | `~/ryu-env` | Python 3.8, `ryu==4.34`, `eventlet==0.30.2` |
| Python cicflowmeter | `~/cicflow-env` | Python 3.14, `cicflowmeter==0.4.2`, `scapy==2.8.0` |

```bash
python3.8 -m venv ~/ryu-env
~/ryu-env/bin/pip install ryu==4.34 eventlet==0.30.2

python3 -m venv ~/cicflow-env
~/cicflow-env/bin/pip install cicflowmeter==0.4.2 scapy==2.8.0
```

> **Keep `cicflowmeter==0.4.2`.** `pcap_to_csv.py` replaces some of its internal functions at runtime.
> Another version may have different internals, and the patch could silently do the wrong thing.
> After any change, run `check_flows.py` and make sure all checks pass.

## Rules

- Attack tools (`hping3`, `nmap`) are run **only inside Mininet**, never on a school or home network.
- Record normal and attack traffic to **separate** PCAP files, so labelling is easy.
- PCAP and CSV files are gitignored. Keep them on your own machine.

## Pipeline

Topology (`topology.py`): one OVS switch `s1` (OpenFlow 1.3), 10 Mbit/s links,
h1 `10.0.0.1` server / victim, h2 and h3 normal clients, h4 attacker.

```bash
# 1. Start the controller (separate terminal, keep it running)
source ~/ryu-env/bin/activate
ryu-manager ryu.app.simple_switch_13

# 2. Capture one scenario per PCAP -> mininet/captures/<scenario>.pcap
cd mininet
sudo python3 run_capture.py --scenario normal --duration 120   # wget + iperf from h2, h3
sudo python3 run_capture.py --scenario dos    --duration 10    # hping3 SYN flood from h4
sudo python3 run_capture.py --scenario probe  --duration 30    # nmap SYN scan from h4
cd ..

# 3. PCAP -> flow CSV (patched cicflowmeter) -> mininet/captures/<scenario>.csv
~/cicflow-env/bin/python mininet/pcap_to_csv.py

# 4. Sanity checks (expected: 4 x PASS)
python3 mininet/check_flows.py
```

5. `notebooks/05_mininet_test.ipynb`: `src.cicflow_adapter.cicflow_to_dataset()` maps the CSV
   to the dataset's 62 features, then predict with `models/best_model.joblib`.

`run_capture.py` turns off TSO/GSO/GRO on every host interface before it captures.
The log shows the result for each interface (`tcp-segmentation-offload: off ...`).

## Differences from the dataset's Java CICFlowMeter

| Problem | Effect if not fixed | Fixed in |
| --- | --- | --- |
| Time unit: Python gives seconds, the dataset uses microseconds | durations and IATs are 10⁶ times too small | `src/cicflow_adapter.py` (× 1,000,000) |
| Column names: Python uses `flow_byts_s`, the dataset uses `Flow Byts/s` | columns don't match | `src/cicflow_adapter.py` (snake_case → `FEATURE_COLS`) |
| Packet length: Python counts `len(packet)` (Ethernet + IP + TCP/UDP headers), Java counts payload only | an empty SYN is 54 bytes instead of 0; all length and byte features are too big | `pcap_to_csv.py` |
| Offload (TSO/GSO/GRO) on Mininet veth interfaces | tcpdump sees merged "packets" of up to ~65,000 bytes | `run_capture.py` |
| cicflowmeter 0.4.2 bug: the first packet of every flow is added twice | packet counts +1, a fake 0 in the IATs | `pcap_to_csv.py` |

Payload length is computed from header fields, not from Scapy's `.payload`, because `.payload`
can also count Ethernet padding:

```
payload = IP total length - IP header length (IHL x 4) - TCP header (data offset x 4) or UDP header (8)
```

## Sanity checks (`check_flows.py`)

| Check | Why |
| --- | --- |
| dos and probe: every flow has `TotLen Fwd Pkts = 0` and `Flow Byts/s = 0` | SYN packets carry no payload. Not 0 means headers are still counted. |
| normal: no packet length above 1460 | MTU 1500 - IP 20 - TCP 20. Larger means offload is still on. (With TCP timestamps the max is 1448.) |
| one normal HTTP flow recomputed by hand from the raw PCAP bytes (no Scapy) | an independent second calculation must give the same 14 feature values |
