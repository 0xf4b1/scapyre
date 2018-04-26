from scapy.layers.inet import *


class ProxySniffer:
    def __init__(self, instance):
        self.instance = instance
        pass

    def start(self):
        """ Starts the proxy to intercept incoming packets """
        print("Using sniffer")
        sniff(iface=self.instance.iface, prn=self.callback_sniffer)

    def callback_sniffer(self, pkt):
        self.instance.callback(pkt)

    def stop(self):
        pass
