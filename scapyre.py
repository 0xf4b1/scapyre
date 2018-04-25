import Queue
import threading

from time import sleep
from scapy.layers.inet import *
from netfilterqueue import NetfilterQueue

from ProxySniffer import ProxySniffer


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

    # last packet time to calculate delta with follow up packet
    last_packet_time = None

    def __init__(
        self,
        ip,
        pcap,
        iface,
        mapping=None,
        buffer_size=1000,
        respect_packet_deltas=True,
        proxy_implementation=ProxySniffer,
    ):
        self.ip = ip
        self.pcap = pcap
        self.iface = iface
        self.mapping = mapping
        self.packet_buffer = Queue.Queue(maxsize=buffer_size)
        self.respect_packet_deltas = respect_packet_deltas
        self.proxy_implementation = proxy_implementation(self)

    def start(self):
        """Call this method to start the replay, it will setup all the threads and configuration for
        the replay and ask to hit return to start to process the first packet"""
        print("Start proxy thread ...")
        # Runs in its own thread because nfqueue continuously listens for incoming packets and blocks.
        # Checksums of the received packets will be stored in a queue to verify if they were received
        proxy_thread = threading.Thread(target=self.proxy_implementation.start)
        proxy_thread.daemon = True
        proxy_thread.start()

        print("Start packet buffer thread ...")
        # Buffer runs in another thread to read packets from the pcap file.
        # The packets need to be buffered to determine for incoming packets if they belong to the replay.
        # The buffered packets are stored in a queue so that they can processed in sequence.
        buffer_thread = threading.Thread(target=self.start_buffer)
        buffer_thread.daemon = True
        buffer_thread.start()

        print("Start replay thread ...")
        # Replay thread processes the packets from the queue in sequence
        replay_thread = threading.Thread(target=self.start_replay)
        replay_thread.daemon = True
        replay_thread.start()

        # main thread, looping until interrupted by the user in case the replay should be aborted
        while True:
            try:
                sleep(1)
            except KeyboardInterrupt:
                print("closing ...")
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
        print("No more packets in pcap file, buffer thread terminating!")

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
            print("not related: " + str(layer.chksum))
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
        s = conf.L2socket(iface=self.iface)
        i = 1
        while True:
            # replay done
            if self.packet_buffer.empty() and self.pcap_ended:
                break
            print("Packet #" + str(i))
            # get next packet from queue, blocks when queue is empty
            packet = self.packet_buffer.get()
            if has_layer(packet):
                layer = get_layer(packet)
                print(packet.summary())
                print("chksum: " + str(layer.chksum))
                print("size: " + str(len(packet)))
                ip_layer = packet.getlayer(IP)
                src = self.map(ip_layer.src)
                dst = self.map(ip_layer.dst)
                # host is source and sends the current packet to dest
                if self.is_related_src(packet):
                    print("Sending packet: src=" + src + ", dst=" + dst)
                    # if option is enabled respect the time between packets
                    if self.respect_packet_deltas and self.last_packet_time is not None:
                        delta = packet.time - self.last_packet_time
                        print("delta: " + str(delta))
                        sleep(delta)
                    # craft next packet with replacement of L2/L3 (the IPs and MACs according to
                    # host mapping) and send it
                    s.send(Ether() / IP(src=src, dst=dst) / layer)
                    self.last_packet_time = packet.time
                # host is destination and waits for the current packet from source
                elif self.is_related_dst(packet):
                    print("Waiting for packet: src=" + src + ", dst=" + dst)
                    # wait for the queue to come up
                    while src not in self.received_packets_queue:
                        sleep(0.1)  # sleep 100ms
                    # gets the next received packet and blocks when empty
                    while layer.chksum not in self.received_packets_queue[src]:
                        sleep(0.1)
                    self.received_packets_queue[src].remove(layer.chksum)
                    self.last_packet_time = packet.time
                # host is not related to current packet, ignore it
                else:
                    print("Not related to packet, ignoring.")
            i += 1

        print("No more packets, replay done! :)")

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
