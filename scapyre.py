import Queue
import threading
import logging

from time import sleep
from scapy.layers.inet import *
from netfilterqueue import NetfilterQueue

from methods import Sniffer


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
        proxy_implementation=Sniffer,
        delay=0.0,
        logfile="replay.log",
    ):
        logging.basicConfig(
            format="%(asctime)s %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            filename=logfile,
            filemode="w",
            level=logging.DEBUG,
        )
        self.ip = ip
        self.pcap = pcap
        self.iface = iface
        self.mapping = mapping
        self.packet_buffer = Queue.Queue(maxsize=buffer_size)
        self.respect_packet_deltas = respect_packet_deltas
        self.delay = delay
        self.proxy_implementation = proxy_implementation(self)

    def start(self):
        """Call this method to start the replay, it will setup all the threads and configuration for
        the replay and ask to hit return to start to process the first packet"""
        logging.info("Start proxy thread ...")
        # Runs in its own thread because nfqueue continuously listens for incoming packets and blocks.
        # Checksums of the received packets will be stored in a queue to verify if they were received
        proxy_thread = threading.Thread(target=self.proxy_implementation.start)
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
        self.proxy_implementation.stop()
        exit(0)

    def start_buffer(self):
        """Reads new packets from the pcap file while the buffer is not full"""
        pcap_reader = PcapReader(self.pcap)
        while True:
            if self.packet_buffer.not_full:
                packet = pcap_reader.read_packet()
                if packet is None:
                    break
                if has_layer(packet):
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
        if has_layer(packet):
            layer = get_layer(packet)
            if self.is_expected(packet):
                # put it in the received packet queue that will be processed in the handle packet thread
                ip_layer = packet.getlayer(IP)
                if ip_layer.src not in self.received_packets_queue:
                    self.received_packets_queue[ip_layer.src] = []
                self.received_packets_queue[ip_layer.src].append(layer.chksum)
                return True
            logging.debug("not related: " + str(layer.chksum))
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
        start_time = time.time()
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
            if has_layer(packet):
                layer = get_layer(packet)
                logging.info(
                    f"{packet.summary()}, chksum: {str(layer.chksum)}, size: {str(len(packet))}, time: {str(packet.time)}"
                )
                ip_layer = packet.getlayer(IP)
                src = self.map(ip_layer.src)
                dst = self.map(ip_layer.dst)

                delta = packet.time + self.delay - (time.time() - start_time)
                logging.info("delta: " + str(delta))

                # host is source and sends the current packet to dest
                if self.is_related_src(packet):
                    # if option is enabled respect the time between packets
                    if self.respect_packet_deltas:
                        if delta > 0:
                            sleep(delta)
                    # craft next packet with replacement of L2/L3 (the IPs and MACs according to host mapping) and send it
                    logging.info(f"Sending packet: src: {src}, dst: {dst}")
                    s.send(Ether() / IP(src=src, dst=dst) / layer)
                # host is destination and waits for the current packet from source
                elif self.is_related_dst(packet):
                    logging.info(
                        f"Waiting for packet: src: {src}, dst: {dst}, expected at: {time.strftime('%H:%M:%S', time.gmtime(time.time() + delta))}"
                    )
                    # wait for the queue to come up
                    while src not in self.received_packets_queue:
                        sleep(0.1)  # sleep 100ms
                    # gets the next received packet and blocks when empty
                    while layer.chksum not in self.received_packets_queue[src]:
                        sleep(0.1)
                    self.received_packets_queue[src].remove(layer.chksum)
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
        self.src = map(packet.getlayer(IP).src, mapping)
        self.dst = map(packet.getlayer(IP).dst, mapping)
        self.sport = get_layer(packet).sport
        self.dport = get_layer(packet).dport
        self.proto = packet.payload.proto
        self.chksum = get_layer(packet).chksum

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


def get_layer(packet):
    if packet.haslayer(TCP):
        return packet.getlayer(TCP)
    elif packet.haslayer(UDP):
        return packet.getlayer(UDP)
    elif packet.haslayer(ICMP):
        return packet.getlayer(ICMP)


def has_layer(packet):
    return packet.haslayer(IP) and (
        packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(ICMP)
    )


def map(ip, mapping=None):
    if mapping is None:
        return ip
    return mapping[ip] if ip in mapping else mapping["default"]
