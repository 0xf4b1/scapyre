import argparse
import json
import logging
import os
import Queue
import threading

from time import sleep, time, gmtime, strftime

from scapy.layers.inet import IP, conf, Ether, ICMP, TCP, UDP, sniff
from scapy.utils import PcapReader


class Sniffer:
    def __init__(self, instance):
        self.instance = instance

    def start(self):
        """Starts the proxy to intercept incoming packets"""
        logging.info("Using sniffer")
        # Drop all the incoming packets so that they are not further processed by the OS to suppress the RST responses
        os.system("iptables -P INPUT DROP")
        sniff(iface=self.instance.iface, prn=self.callback_sniffer)

    def callback_sniffer(self, pkt):
        self.instance.callback(pkt)

    def stop(self):
        logging.info("Flushing iptables.")
        os.system("iptables -F")
        os.system("iptables -X")


class Netfilter:
    def __init__(self, instance):
        self.instance = instance

    def start(self):
        """Starts the proxy to intercept incoming packets"""
        # Starts the netfilter queue, the nfqueue.run() method listens for
        # incoming packets and calls the callback method and blocks
        logging.info("Using nfqueue")
        # Sets up nfqueue so that packets will first put in a queue to process them
        # here before they are processed by the OS when accepted
        os.system(
            "iptables -A INPUT -i " + self.instance.iface + " -j NFQUEUE --queue-num 1"
        )
        from netfilterqueue import NetfilterQueue

        nfqueue = NetfilterQueue()
        nfqueue.bind(1, self.callback_nfqueue)
        nfqueue.run()

    def callback_nfqueue(self, pkt):
        """Callback method for the nfqueue implementation that uses the default callback
        and additionally accepts or drops packets"""
        packet = IP(pkt.get_payload())
        if self.instance.callback(packet):
            # packet is related to the replay, drop it here so that it will not further processed by the OS
            pkt.drop()
        else:
            # the packet is not part of the replay, accept it so that it will treated normally
            pkt.accept()

    def stop(self):
        logging.info("Flushing iptables.")
        os.system("iptables -F")
        os.system("iptables -X")


class Scapyre:
    # list of packet's checksums that are expected by the host
    expected_packets = []

    # queues of received packets mapped by sender host IP
    received_packets_queue = {}

    # buffer of packets that is filled by the buffer thread
    # and processed in sequence by the replay thread
    packet_buffer = None

    # indicates that the buffer thread will not produce further more packets
    # to that the replay can successfully terminate
    pcap_ended = False

    def __init__(
        self,
        ip,
        pcap,
        iface,
        mapping=None,
        buffer_size=10000,
        respect_packet_deltas=True,
        netfilter=False,
        delay=0.0,
        logfile="replay.log",
    ):
        logging.basicConfig(
            format="%(asctime)s %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.DEBUG,
        )
        logging.getLogger().addHandler(logging.FileHandler(filename=logfile, mode="w"))
        self.ip = ip
        self.pcap = pcap
        self.iface = iface
        self.mapping = mapping
        self.packet_buffer = Queue.Queue(maxsize=buffer_size)
        self.respect_packet_deltas = respect_packet_deltas
        self.delay = delay
        self.collector = Netfilter(self) if netfilter else Sniffer(self)

    def start(self):
        """Call this method to start the replay, it will setup all the threads and configuration for
        the replay and ask to hit return to start to process the first packet"""
        logging.info("Start proxy thread ...")
        # Runs in its own thread because nfqueue continuously listens for incoming packets and blocks.
        # Checksums of the received packets will be stored in a queue to verify if they were received
        proxy_thread = threading.Thread(target=self.collector.start)
        proxy_thread.daemon = True
        proxy_thread.start()

        logging.info("Start packet buffer thread ...")
        # Buffer runs in another thread to read packets from the pcap file.
        # The packets need to be buffered to determine for incoming packets if they belong to the replay.
        # The buffered packets are stored in a queue so that they can processed in sequence.
        buffer_thread = threading.Thread(target=self.start_buffer)
        buffer_thread.daemon = True
        buffer_thread.start()

        logging.info("Start replay thread ...")
        # Replay thread processes the packets from the queue in sequence
        replay_thread = threading.Thread(target=self.start_replay)
        replay_thread.daemon = True
        replay_thread.start()

        # main thread, looping until interrupted by the user in case the replay should be aborted
        while True:
            try:
                sleep(1)
            except KeyboardInterrupt:
                self.stop()

    def stop(self):
        logging.info("closing ...")
        self.collector.stop()
        exit(0)

    def start_buffer(self):
        """Reads new packets from the pcap file while the buffer is not full"""
        pcap_reader = PcapReader(self.pcap)
        while True:
            if self.packet_buffer.not_full:
                packet = pcap_reader.read_packet()
                if packet is None:
                    break
                if has_transport_layer(packet):
                    if self.is_related(packet):
                        self.packet_buffer.put(packet)
                    if self.is_related_dst(packet):
                        self.expected_packets.append(
                            PacketMetadata(packet, self.mapping)
                        )

        self.pcap_ended = True
        logging.info("No more packets in pcap file, buffer thread terminating!")
        if self.packet_buffer.empty():
            self.stop()

    def callback(self, packet):
        """Packet callback method to process a received packet and decide whether it is related to the replay or not"""
        if has_transport_layer(packet):
            checksum = get_transport_layer(packet).chksum
            if self.is_expected(packet):
                # put it in the received packet queue that will be processed in the handle packet thread
                ip_layer = packet.getlayer(IP)
                if ip_layer.src not in self.received_packets_queue:
                    self.received_packets_queue[ip_layer.src] = []
                self.received_packets_queue[ip_layer.src].append(checksum)
                return True
            logging.debug("not related: " + str(checksum))
        return False

    def is_expected(self, packet):
        ip = self.map(self.ip)
        if packet.getlayer(IP).dst != ip:
            return False
        metadata = PacketMetadata(packet)
        if metadata in self.expected_packets:
            self.expected_packets.remove(metadata)
            return True
        return False

    def start_replay(self):
        """Starts the main replay where the packets from the buffer are processed in sequence"""
        if self.delay > 0:
            logging.info("delayed start, waiting for: " + str(self.delay))
            sleep(self.delay)
        start_time = time()
        logging.info("start time: " + str(start_time))
        s = conf.L2socket(iface=self.iface)
        i = 1
        while True:
            # replay done
            if self.packet_buffer.empty() and self.pcap_ended:
                break
            # get next packet from queue, blocks when queue is empty
            packet = self.packet_buffer.get()
            logging.info("Packet #" + str(i))
            if has_transport_layer(packet):
                transport_layer = get_transport_layer(packet)
                logging.info(
                    f"{packet.summary()}, chksum: {str(transport_layer.chksum)}, size: {str(len(packet))}, time: {str(packet.time)}"
                )
                ip_layer = packet.getlayer(IP)
                src = self.map(ip_layer.src)
                dst = self.map(ip_layer.dst)

                delta = packet.time + self.delay - (time() - start_time)
                logging.info("delta: " + str(delta))

                # host is source and sends the current packet to dest
                if self.is_related_src(packet):
                    # if option is enabled respect the time between packets
                    if self.respect_packet_deltas:
                        if delta > 0:
                            sleep(delta)
                    # craft next packet with replacement of L2/L3 (the IPs and MACs according to host mapping) and send it
                    logging.info(f"Sending packet: src: {src}, dst: {dst}")
                    s.send(Ether() / IP(src=src, dst=dst) / transport_layer)
                # host is destination and waits for the current packet from source
                elif self.is_related_dst(packet):
                    logging.info(
                        f"Waiting for packet: src: {src}, dst: {dst}, expected at: {strftime('%H:%M:%S', gmtime(time() + delta))}"
                    )
                    # wait for the queue to come up
                    while src not in self.received_packets_queue:
                        sleep(0.1)  # sleep 100ms
                    # gets the next received packet and blocks when empty
                    while (
                        transport_layer.chksum not in self.received_packets_queue[src]
                    ):
                        sleep(0.1)
                    self.received_packets_queue[src].remove(transport_layer.chksum)
                # host is not related to current packet, ignore it
                else:
                    logging.warning("Not related to packet, ignoring.")
            i += 1

        logging.info("No more packets, replay done! :)")
        self.stop()

    def is_related(self, packet):
        return self.is_related_src(packet) or self.is_related_dst(packet)

    def is_related_src(self, packet):
        ip_layer = packet.getlayer(IP)
        return ip_layer.src == self.ip or (
            self.mapping is not None
            and ip_layer.src not in self.mapping
            and self.ip == "default"
        )

    def is_related_dst(self, packet):
        ip_layer = packet.getlayer(IP)
        return ip_layer.dst == self.ip or (
            self.mapping is not None
            and ip_layer.dst not in self.mapping
            and self.ip == "default"
        )

    def map(self, ip):
        return map(ip, self.mapping)


class PacketMetadata:
    src = None
    dst = None
    sport = None
    dport = None
    proto = None
    chksum = None

    def __init__(self, packet, mapping=None):
        # 3rd layer: IP
        layer = packet.getlayer(IP)
        self.src = map(layer.src, mapping)
        self.dst = map(layer.dst, mapping)
        self.proto = layer.proto

        # 4th layer: TCP/UDP/ICMP
        if has_transport_layer(packet):
            layer = get_transport_layer(packet)
            self.chksum = layer.chksum
            if type(layer) is not ICMP:
                self.sport = layer.sport
                self.dport = layer.dport

    def __eq__(self, other):
        if isinstance(self, other.__class__):
            return self.__dict__ == other.__dict__
        return NotImplemented

    def __ne__(self, other):
        x = self.__eq__(other)
        if x is not NotImplemented:
            return not x
        return NotImplemented

    def __hash__(self):
        return hash(tuple(sorted(self.__dict__.items())))


def has_transport_layer(packet):
    return packet.haslayer(IP) and (
        packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(ICMP)
    )


def get_transport_layer(packet):
    if packet.haslayer(TCP):
        return packet.getlayer(TCP)
    elif packet.haslayer(UDP):
        return packet.getlayer(UDP)
    elif packet.haslayer(ICMP):
        return packet.getlayer(ICMP)


def map(ip, mapping=None):
    if mapping is None:
        return ip
    return mapping[ip] if ip in mapping else mapping["default"]


if __name__ == "__main__":
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
        "--start-delayed",
        type=float,
        dest="delay",
        default=0.0,
        help="Wait time in seconds till the replay should start",
    )

    parser.add_argument(
        "--logfile",
        type=str,
        dest="logfile",
        default="replay.log",
        help="File to store the logs of the replay",
    )

    parser.add_argument(
        "--netfilter",
        dest="netfilter",
        default=False,
        action="store_true",
        help="Use netfilterqueue instead of sniffer",
    )

    args = parser.parse_args()

    # Create instance of the replay, respect_delays true cares about the intermediate packet deltas
    replay = Scapyre(
        args.ip,
        args.pcap,
        args.iface,
        mapping=args.mapping,
        respect_packet_deltas=args.deltas,
        delay=args.delay,
        logfile=args.logfile,
        netfilter=args.netfilter,
    )
    replay.start()
