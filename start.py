from scapyre import Scapyre

# cofiguration and startup file

# the pcap file for the replay
pcap = 'some-pcap-file.pcap'

# Host IP from the pcap file that is handled by this host
ip = 'default'

# the host interface that will be used
iface = 'eth0'

# mapping of host IP in the pcap file -> host IP in the replay environment.
# it is possible that one host handles the packets of multiple hosts in the pcap file.
# Mapping 'default' to one host means it handles all the traffic from hosts that were not mapped
mapping = {'192.168.1.114': '192.168.1.1', '158.69.209.193': '192.168.2.1', 'default': '192.168.100.1'}

# Create instance of the replay, respect_delays true cares about the intermediate packet deltas
replay = Scapyre(ip, pcap, iface, mapping=mapping, respect_packet_deltas=False)
replay.start()
