'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *
import json
#传入arp字典，输出优先级，这是排序用的
def age_return(a):
    return a[1][1]

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    #定义arp_table结构：key为mac地址，value为两个元素的列表，分别为接口和流量
    arp_table={}
    table_capacity=5
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        
        if packet[0].src in arp_table.keys():
            arp_table[packet[0].src][0]=fromIface #更新端口号
        else:
            if len(arp_table)==table_capacity:
                sorted_arp=sorted(arp_table.items(),key=age_return)
                del arp_table[sorted_arp[0][0]] #删除流量最小entry
            else:
                pass 
            arp_table[packet[0].src]=[fromIface,0] #新插入entry，记录0流量

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        elif eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if packet[0].dst in arp_table.keys(): #当arp表有存该包目标地址时直接转发
                arp_table[packet[0].dst][1]+=1 #流量+1
                net.send_packet(arp_table[packet[0].dst][0],packet)
                log_info (f"Single packet {packet} to {arp_table[packet[0].dst][0]}")
                with open('arp_table.txt','a') as f:
                    f.write(str(arp_table)+'\n')
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
                with open('arp_table.txt','a') as f:
                    f.write(str(arp_table)+'\n')
    net.shutdown()

#Deploy
#server1 ping -c 1 client
#server2 ping -c 1 server1