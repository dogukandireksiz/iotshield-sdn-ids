"""Run one traffic scenario in the IDS topology and save it as a PCAP"""
import argparse
import os 
import signal
import time

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

from topology import IDSTopo

CAPTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),"captures")
VICTIM_IP = "10.0.0.1"

def disable_offload(net):
    """Turn off TSO/GSO/GRO so tcpdump sees real MTU-sized packets, not merged segments."""
    for host in net.hosts:
        for intf in host.intfNames():
            if intf == "lo":
                continue
            host.cmd(f"ethtool -K {intf} tso off gso off gro off")
            state = host.cmd(f"ethtool -k {intf} | grep -E '^(tcp-segmentation|generic-segmentation|generic-receive)-offload'")
            info(f"*** {host.name} {intf}: {' | '.join(state.split(chr(10))).strip(' |')}\n")


def start_services(h1):
    h1.cmd("python3 -m http.server 80  > /dev/null 2>&1 &")
    h1.cmd("iperf -s > /dev/null 2>&1 &")

def start_capture(h1, pcap_path):
    out = h1.cmd(f"tcpdump -i h1-eth0 -Z root -w {pcap_path} ip > /dev/null 2>&1 & echo $!")
    return int(out.strip().split()[-1])  #PID of tcpdump


def stop_capture(pid):
    os.kill(pid, signal.SIGINT)
    time.sleep(1)


def normal_traffic(net, duration):
    h2, h3 = net.get("h2","h3")
    end = time.time() + duration
    while time.time() < end:
        h2.cmd(f"wget -q -O /dev/null http://{VICTIM_IP}")
        h3.cmd(f"iperf -c {VICTIM_IP} -t 2 > /dev/null")
        time.sleep(1)

def dos_traffic(net,duration):
    h4 = net.get("h4")
    h4.cmd(f"timeout {duration} hping3 -S -p 80 --flood {VICTIM_IP} > /dev/null 2>&1")

def probe_traffic(net, duration):
    h4 = net.get("h4")
    h4.cmd(f"timeout {duration} nmap -e h4-eth0 -Pn -n -sS -T4 -p 1-1000 {VICTIM_IP} < /dev/null 2>&1")
    



SCENARIOS = {"normal":normal_traffic, "dos":dos_traffic, "probe":probe_traffic}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=SCENARIOS.keys(), required=True)
    parser.add_argument("--duration", type=int, default=30)
    args = parser.parse_args()

    os.makedirs(CAPTURE_DIR,exist_ok=True)
    pcap_path = os.path.join(CAPTURE_DIR, f"{args.scenario}.pcap")

    net = Mininet(topo=IDSTopo(), controller=None, switch=OVSSwitch, link=TCLink)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    net.start()

    try:
        disable_offload(net)
        net.pingAll()
        h1 = net.get("h1")
        start_services(h1)
        pid = start_capture(h1,pcap_path)
        time.sleep(1)
        SCENARIOS[args.scenario](net,args.duration)
        stop_capture(pid)
        info(f"*** Saved {pcap_path}\n")
    finally:
        net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    main()