"""Sanity checks for flow CSVs made by pcap_to_csv.py (payload-only lengths).

1. dos and probe (SYN flood / SYN scan): every flow has totlen_fwd_pkts == 0 and flow_byts_s == 0
2. normal: no packet length is above 1460 (would mean TSO/GRO merged segments)
3. one normal TCP flow is recomputed by hand from the raw PCAP bytes (no Scapy)
   and compared with its CSV row

Standard library only:  python3 mininet/check_flows.py [captures_dir]
"""
import csv
import os
import socket
import struct
import sys

MAX_PAYLOAD = 1460


def read_rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def check_zero_payload(rows, name):
    bad = [r for r in rows if float(r["totlen_fwd_pkts"]) != 0 or float(r["flow_byts_s"]) != 0]
    bwd = sum(float(r["totlen_bwd_pkts"]) != 0 for r in rows)
    print(f"[{name}] {len(rows)} flows, {len(bad)} with TotLen Fwd Pkts or Flow Byts/s != 0"
          f"  (info: {bwd} flows with TotLen Bwd Pkts != 0)")
    for r in bad[:5]:
        print(f"    {r['src_ip']}:{r['src_port']} -> {r['dst_ip']}:{r['dst_port']} "
              f"totlen_fwd={r['totlen_fwd_pkts']} flow_byts_s={r['flow_byts_s']}")
    return not bad


def check_max_len(rows, name):
    cols = ("fwd_pkt_len_max", "bwd_pkt_len_max", "pkt_len_max")
    biggest = max(float(r[c]) for r in rows for c in cols)
    over = [r for r in rows if any(float(r[c]) > MAX_PAYLOAD for c in cols)]
    print(f"[{name}] largest packet length = {biggest:.0f}, flows above {MAX_PAYLOAD}: {len(over)}")
    return not over


def read_pcap(path):
    """Yield (timestamp_us, ip_bytes) for Ethernet/IPv4 records, parsed by hand.

    Timestamps are integer microseconds, so durations have no float rounding error.
    """
    with open(path, "rb") as f:
        header = f.read(24)
        magic = header[:4]
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                  b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}[magic]
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        assert linktype == 1, f"expected Ethernet capture, got linktype {linktype}"
        while rec := f.read(16):
            sec, frac, incl, _ = struct.unpack(endian + "IIII", rec)
            frame = f.read(incl)
            if struct.unpack("!H", frame[12:14])[0] != 0x0800:     # IPv4 only
                continue
            yield sec * 1_000_000 + (frac // 1000 if nano else frac), frame[14:]


def parse_tcp(ip):
    """Return (src, sport, dst, dport, payload_len) for a TCP packet, else None."""
    if ip[9] != 6:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total_len = struct.unpack("!H", ip[2:4])[0]
    sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
    data_offset = (ip[ihl + 12] >> 4) * 4
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    return src, sport, dst, dport, total_len - ihl - data_offset


def hand_check(rows, pcap_path):
    # A short web flow whose 4-tuple appears once in the CSV, so it cannot be split.
    key = lambda r: (r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"])
    counts = {}
    for r in rows:
        counts[key(r)] = counts.get(key(r), 0) + 1
    candidates = [r for r in rows if r["protocol"] == "6" and "80" in (r["src_port"], r["dst_port"])
                  and counts[key(r)] == 1 and float(r["totlen_fwd_pkts"]) > 0]
    if not candidates:
        print("[hand] no suitable HTTP flow found")
        return False
    row = candidates[0]
    fwd = (row["src_ip"], int(row["src_port"]), row["dst_ip"], int(row["dst_port"]))
    bwd = (fwd[2], fwd[3], fwd[0], fwd[1])

    pkts = []
    for ts, ip in read_pcap(pcap_path):
        t = parse_tcp(ip)
        if t and t[:4] in (fwd, bwd):
            pkts.append((ts, "fwd" if t[:4] == fwd else "bwd", t[4]))

    print(f"[hand] flow {fwd[0]}:{fwd[1]} -> {fwd[2]}:{fwd[3]}, {len(pkts)} packets in PCAP:")
    t0 = pkts[0][0]
    for ts, d, n in pkts:
        print(f"    t={(ts - t0) / 1e6:9.6f}s  {d}  payload={n}")

    f_len = [n for _, d, n in pkts if d == "fwd"]
    b_len = [n for _, d, n in pkts if d == "bwd"]
    duration = (pkts[-1][0] - t0) / 1e6                       # seconds, like the raw CSV
    iats = [(b[0] - a[0]) / 1e6 for a, b in zip(pkts, pkts[1:])]
    expected = {
        "tot_fwd_pkts": len(f_len),
        "tot_bwd_pkts": len(b_len),
        "totlen_fwd_pkts": sum(f_len),
        "totlen_bwd_pkts": sum(b_len),
        "fwd_pkt_len_max": max(f_len, default=0),
        "fwd_pkt_len_min": min(f_len, default=0),
        "fwd_pkt_len_mean": sum(f_len) / len(f_len) if f_len else 0,
        "bwd_pkt_len_max": max(b_len, default=0),
        "bwd_pkt_len_mean": sum(b_len) / len(b_len) if b_len else 0,
        "fwd_act_data_pkts": sum(n > 0 for n in f_len),
        "flow_duration": duration,
        "flow_byts_s": (sum(f_len) + sum(b_len)) / duration if duration else 0,
        "flow_iat_mean": sum(iats) / len(iats) if iats else 0,
        "flow_iat_min": min(iats, default=0),
    }

    ok = True
    print(f"    {'feature':<18}{'by hand':>16}{'CSV':>16}")
    for col, exp in expected.items():
        got = float(row[col])
        match = abs(got - exp) <= 1e-6 * max(1.0, abs(exp))
        ok &= match
        print(f"    {col:<18}{exp:>16.6f}{got:>16.6f}  {'OK' if match else 'MISMATCH'}")
    return ok


def main():
    cap = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")
    results = {}
    for name in ("dos", "probe"):
        results[f"{name}: zero payload"] = check_zero_payload(read_rows(os.path.join(cap, f"{name}.csv")), name)
    normal = read_rows(os.path.join(cap, "normal.csv"))
    results["normal: max length <= 1460"] = check_max_len(normal, "normal")
    results["normal: hand-computed flow"] = hand_check(normal, os.path.join(cap, "normal.pcap"))

    print()
    for label, ok in results.items():
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
