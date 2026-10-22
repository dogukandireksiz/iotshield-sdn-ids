# Mininet + Ryu test (Faz 7)

Goal: train on ASEADOS-SDN-IoT, test on our own SDN traffic, and measure the drop (domain shift).

## Environment

Ryu needs an older Python (3.8/3.9). Use a **separate** virtual environment here, not the main `.venv`:

```bash
python3.9 -m venv .venv-ryu
source .venv-ryu/bin/activate
pip install ryu
```

Mininet is installed on the Ubuntu VM itself (`sudo apt install mininet`).

## Rules

- Attack tools (`hping3`, `nmap`) are run **only inside Mininet**, never on a school or home network.
- Record normal and attack traffic to **separate** PCAP files, so labelling is easy.
- PCAP files are gitignored. Keep them on your own machine.

## Pipeline

1. Topology: 1–2 switches, 4–5 hosts, Ryu controller
2. Normal traffic: ping, wget (simple HTTP server), iperf
3. Attack traffic: hping3 (DoS), nmap (Probe)
4. `tcpdump` → PCAP → CICFlowMeter → flow CSV
5. Rename columns to the dataset's names (table below), then `src.preprocessing.clean(df, drop_duplicates=False)`, then predict with `models/best_model.joblib`

## Column name mapping

The dataset uses **Java** CICFlowMeter names (`Flow Byts/s`, `Tot Fwd Pkts`). The Python `cicflowmeter` package produces different names. Fill this table in as you go:

| Python cicflowmeter | Dataset (Java CICFlowMeter) |
| --- | --- |
| | |
