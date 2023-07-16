'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *
import time

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
        #记录当前时间
        current_time=time.time() 
        #遍历，超时即删除
        for mac_addr in list(arp_table.keys()): 
            if current_time - arp_table[mac_addr][1] >=10.0:
                del arp_table[mac_addr]
        
        #记录当前发来的包的时间戳、地址、端口号
        arp_table[packet[0].src] = [fromIface,current_time]

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        elif eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if packet[0].dst in arp_table.keys(): #当arp表有存该包目标地址时直接转发
                net.send_packet(arp_table[packet[0].dst][0],packet)
                log_info (f"Single packet {packet} to {arp_table[packet[0].dst][0]}")
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()

#Deploy
#client ping -c 1 server1
#10s后执行相同操作。