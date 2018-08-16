from netfilterqueue import NetfilterQueue

from scapy.layers.inet import *


class Netfilter:
    def __init__(self, instance):
        self.instance = instance
        pass

    def start(self):
        """ Starts the proxy to intercept incoming packets """
        # Starts the netfilter queue, the nfqueue.run() method listens for
        # incoming packets and calls the callback method and blocks
        print("Using nfqueue")
        # Sets up nfqueue so that packets will first put in a queue to process them
        # here before they are processed by the OS when accepted
        os.system("iptables -A INPUT -i " + self.instance.iface + " -j NFQUEUE --queue-num 1")
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, self.callback_nfqueue)
        nfqueue.run()

    def callback_nfqueue(self, pkt):
        """ Callback method for the nfqueue implementation that uses the default callback
         and additionally accepts or drops packets """
        packet = IP(pkt.get_payload())
        if self.instance.callback(packet):
            # packet is related to the replay, drop it here so that it will not further processed by the OS
            pkt.drop()
        else:
            # the packet is not part of the replay, accept it so that it will treated normally
            pkt.accept()

    def stop(self):
        print("Flushing iptables.")
        os.system('iptables -F')
        os.system('iptables -X')
