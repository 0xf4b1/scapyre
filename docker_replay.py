#!/usr/bin/python
"""
Create all hosts as docker containers from a PCAP file and do the replay
"""
import argparse
import os

from scapy.layers.inet import *


def start_docker_replay(pcap):
    directory, filename = os.path.split(pcap)

    print("Extracting host IP addresses from PCAP file")
    hosts = set()
    for p in PcapReader(pcap):
        if IP in p:
            if p[IP].src not in hosts:
                hosts.add(p[IP].src)
            if p[IP].dst not in hosts:
                hosts.add(p[IP].dst)

    mapping = (
        "{" + ", ".join([f"\"{ip}\": \"10{ip[ip.find('.'):]}\"" for ip in hosts]) + "}"
    )
    print(mapping)

    print("Starting docker containers")
    for ip in hosts:
        os.system(
            f"xterm -title {ip} -hold -e docker run -it -v {directory}:/data --network scapyre --ip 10{ip[ip.find('.'):]} scapyre /data/{filename} eth0 {ip} --enable-deltas --mapping '{mapping}' &"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scapyre in Docker")
    parser.add_argument("pcap", type=str, help="PCAP file to replay")
    args = parser.parse_args()
    start_docker_replay(args.pcap)
