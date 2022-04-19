#!/usr/bin/env python3
import sys
import socket
import random
import time
from threading import Thread, Event
from scapy.all import *


class Sniffer(Thread):
    '''
    创建一个Sniffer的类，抓包
    '''
    def  __init__(self, interface="eth0"):
        
        super(Sniffer, self).__init__()

        self.interface = interface
        self.my_mac = get_if_hwaddr(interface) 
        self.daemon = True

        self.socket = None
        self.stop_sniffer = Event() #创建一个停止抓包的Event

    def isNotOutgoing(self, pkt):
        # 如果packet的源Mac地址不是我本身的Mac，就True 不然就False
        return pkt[Ether].src != self.my_mac

    def run(self):
        # 创建一个Layer 2的socket，只保留IP packet
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=self.interface,
            filter="ip"
        )
        sniff(opened_socket=self.socket, prn=self.print_packet, lfilter=self.isNotOutgoing, stop_filter=self.should_stop_sniffer)

    def join(self, timeout=None):
        # 终止我们的sniffer
        self.stop_sniffer.set()
        super(Sniffer, self).join(timeout)

    def should_stop_sniffer(self, packet):
        # 如果停止抓包的Event被设置，不再抓包
        return self.stop_sniffer.isSet()

    def print_packet(self, packet):
        print("[!] A packet was reflected from the switch: ")
        #packet.show()
        ether_layer = packet.getlayer(Ether) #二层的包
        print(("[!] Info: {src} -> {dst}\n".format(src=ether_layer.src, dst=ether_layer.dst)))

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0" 
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def send_packet(iface, addr):
    '''
    构造一个Ether + Ip 的包
    '''
    input("Press the return key to send a packet:")
    print("Sending on interface %s to %s\n" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='00:01:02:03:04:05') # 设置Header
    pkt = pkt /IP(dst=addr)
    sendp(pkt, iface=iface, verbose=False)

def main():

    addr = "10.0.0.2"
    addr = socket.gethostbyname(addr)
    iface = get_if()

    listener = Sniffer(iface)
    listener.start()
    time.sleep(0.1)

    try:
        while True:
            send_packet(iface, addr)
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("[*] Stop sniffing")
        listener.join(2.0)

        if listener.isAlive():
            listener.socket.close()

if __name__ == '__main__':
    main()