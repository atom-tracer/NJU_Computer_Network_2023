'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    arp_table={}

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
            
        #更改arp表：以后发往src地址的包将转发至fromIface
        arp_table[packet[0].src]=fromIface 


        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        elif eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if packet[0].dst in arp_table.keys(): #当arp表有存该包目标地址时直接转发
                net.send_packet(arp_table[packet[0].dst],packet)
                log_info (f"Single packet {packet} to {arp_table[packet[0].dst]}")#虽然不知道有什么用但是还是照着写了
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
#Deploy
#client ping -c 1 server1