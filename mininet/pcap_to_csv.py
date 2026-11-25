"""PCAP -> flow CSV with the Python cicflowmeter, patched to count payload bytes only
(and to stop counting the first packet of each flow twice, see apply_patch()).

The Python cicflowmeter measures packet length with len(packet), which includes the
Ethernet, IP and TCP/UDP headers. The Java CICFlowMeter that built the ASEADOS dataset
counts payload bytes only. This script patches the length functions at runtime and then
runs cicflowmeter; the installed package in site-packages is not modified.

Payload length is computed from header fields, not from Scapy's `.payload`, because
`.payload` would also count Ethernet padding:

    payload = IP total length - IP header length - TCP/UDP header length

Run with the cicflowmeter environment:
    ~/cicflow-env/bin/python mininet/pcap_to_csv.py                      # normal, dos, probe
    ~/cicflow-env/bin/python mininet/pcap_to_csv.py in.pcap out.csv      # one file
"""
import os
import sys

from scapy.layers.inet import IP, TCP, UDP

from cicflowmeter.flow import Flow
from cicflowmeter.features.flow_bytes import FlowBytes
from cicflowmeter.features.packet_count import PacketCount
from cicflowmeter.features.packet_length import PacketLength
from cicflowmeter.features.context import PacketDirection
from cicflowmeter.sniffer import create_sniffer

CAPTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")
SCENARIOS = ("normal", "dos", "probe")


def payload_len(packet):
    """TCP/UDP payload bytes, from the IP total length field (ignores Ethernet padding)."""
    ip = packet[IP]
    if TCP in packet:
        l4_header = packet[TCP].dataofs * 4
    elif UDP in packet:
        l4_header = 8
    else:
        l4_header = 0
    return max(ip.len - ip.ihl * 4 - l4_header, 0)


def _lengths(flow, packet_direction=None):
    return [
        payload_len(packet)
        for packet, direction in flow.packets
        if packet_direction is None or direction == packet_direction
    ]


def apply_patch():
    # Bug fix (cicflowmeter 0.4.2): FlowSession.process() creates Flow(pkt) -- which already
    # stores pkt -- and then calls flow.add_packet(pkt) again, so the first packet of every
    # flow is counted twice and a fake 0 is added to the IATs. Start each flow empty and let
    # add_packet() store the first packet once.
    original_init = Flow.__init__

    def init_without_first_packet(self, packet, direction):
        original_init(self, packet, direction)
        self.packets = []

    Flow.__init__ = init_without_first_packet

    # Packet length statistics: totlen_*, *_pkt_len_*, pkt_size_avg, seg_size_avg, subflow_*_byts
    PacketLength.get_packet_length = lambda self, packet_direction=None: _lengths(
        self.flow, packet_direction
    )
    # Byte totals: flow_byts_s = get_bytes() / duration
    FlowBytes.get_bytes = lambda self: sum(_lengths(self.flow))
    FlowBytes.get_bytes_sent = lambda self: sum(_lengths(self.flow, PacketDirection.FORWARD))
    FlowBytes.get_bytes_received = lambda self: sum(_lengths(self.flow, PacketDirection.REVERSE))
    # fwd_act_data_pkts: number of packets with payload (original uses .payload -> padding)
    PacketCount.has_payload = lambda self, packet_direction=None: sum(
        1 for n in _lengths(self.flow, packet_direction) if n > 0
    )


def convert(pcap_path, csv_path):
    sniffer, session = create_sniffer(pcap_path, None, "csv", csv_path)
    sniffer.start()
    sniffer.join()
    session.flush_flows()   # scapy's toPacketList() already wrote the flows and closed the file
    print(f"{pcap_path} -> {csv_path}")


def main():
    apply_patch()
    if len(sys.argv) == 3:
        convert(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 1:
        for name in SCENARIOS:
            convert(os.path.join(CAPTURE_DIR, f"{name}.pcap"), os.path.join(CAPTURE_DIR, f"{name}.csv"))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
