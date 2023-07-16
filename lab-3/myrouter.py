#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = {}
        self.interfaces=net.interfaces()
        self.ip_list=[intf.ipaddr for intf in self.interfaces]
        self.mac_list=[intf.ethaddr for intf in self.interfaces]

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        arp=packet.get_header(Arp)
        if not arp:
            return

        #nodify the arp_table
        for ip_addr in list(self.arp_table.keys()): 
            if timestamp - self.arp_table[ip_addr][1] >=100.0:
                del self.arp_table[ip_addr]
        #modify the arp_table

        if arp.targetprotoaddr in self.ip_list:
            self.arp_table[arp.senderprotoaddr] = [arp.senderhwaddr,timestamp]
            self.export_arp_table()
            if arp.operation==ArpOperation.Request:
                index=self.ip_list.index(arp.targetprotoaddr)
                reply_pkt=create_ip_arp_reply(self.mac_list[index],arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                self.net.send_packet(ifaceName,reply_pkt)
                log_info("send a arp reply")
            else:
                log_info("this is not a arp request")
        else:
            log_info("no match interface")

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()
    
    def export_arp_table(self):
        with open('arp_table.txt','a') as f:
            f.write(str(self.arp_table)+'\n')

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
