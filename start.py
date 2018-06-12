import argparse
import json

from scapyre import Scapyre


parser = argparse.ArgumentParser(description="Scapyre")

parser.add_argument("pcap", type=str, help="PCAP file to replay")

parser.add_argument(
    "iface", type=str, help="Interface that will be used for the replay"
)

parser.add_argument(
    "ip",
    type=str,
    help="IP address of a host in the PCAP that will be replayed by this host",
)

parser.add_argument(
    "--mapping",
    type=json.loads,
    default=None,
    help="Remapping of host IPs in the PCAP and actual host IPs in the replay environment",
)

parser.add_argument(
    "--enable-deltas",
    dest="deltas",
    default=False,
    action="store_true",
    help="Respect deltas between two packets",
)

parser.add_argument(
    "--logfile",
    dest="logfile",
    default="replay.log",
    help="File to store the logs of the replay",
)

args = parser.parse_args()

# Create instance of the replay, respect_delays true cares about the intermediate packet deltas
replay = Scapyre(
    args.ip,
    args.pcap,
    args.iface,
    mapping=args.mapping,
    respect_packet_deltas=args.deltas,
    logfile=args.logfile,
)
replay.start()
