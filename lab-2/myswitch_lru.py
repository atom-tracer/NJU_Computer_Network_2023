'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *
import json
# 定义了一个节点，相当于arp表的一个表项
class ArpNode:
    def __init__(self,mac_addr=0,port=0):
        self.mac_addr=mac_addr
        self.port=port
        self.next=None
        self.prev=None

class ArpTable:
    def __init__(self,capacity=5):#初始化函数
        self.capacity=capacity
        self.head=ArpNode()
        self.tail=ArpNode()
        self.head.next=self.tail
        self.tail.prev=self.head
        self.arp_hash={}


    def src_add(self,mac_addr,port):#处理包的源地址
        if mac_addr in self.arp_hash.keys():
            self.arp_hash[mac_addr].port=port
        else:
            if len(self.arp_hash)==self.capacity:
                self.remove_tail()
            else:
                pass
            new_node=ArpNode(mac_addr,port)
            self.arp_hash[mac_addr]=new_node
            self.add_to_head(new_node)

    def dst_add(self,mac_addr):#处理包的目的地址
        if mac_addr in self.arp_hash.keys():
            self.move_to_head(self.arp_hash[mac_addr])
            return self.arp_hash[mac_addr].port #告诉主函数，arp表中有该地址，可以直接转发,并且直接返回端口号
        else:
            return False #告诉主函数，arp表中没有该地址，需要广播


    def add_to_head(self,node):
        node.next=self.head.next
        node.prev=self.head
        node.next.prev=node
        node.prev.next=node
    
    def removeNode(self,node):
        node.prev.next=node.next
        node.next.prev=node.prev

    def move_to_head(self,node):
        self.removeNode(node)
        self.add_to_head(node)

    def remove_tail(self):
        del self.arp_hash[self.tail.prev.mac_addr]
        self.removeNode(self.tail.prev)

    def print_arp(self):#打印arp表
        table_to_print={}
        tra_node=self.head.next
        while tra_node.next!=None:
            table_to_print[tra_node.mac_addr]=tra_node.port
            tra_node=tra_node.next
        with open('arp_table.txt','a') as f:
            f.write(str(table_to_print)+'\n')


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    arp_table=ArpTable(5)
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        
        arp_table.src_add(packet[0].src,fromIface)

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        elif eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if packet[0].dst=='ff:ff:ff:ff:ff:ff':
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
            else:
                floodjudge=arp_table.dst_add(packet[0].dst)
                if floodjudge==False: #当没有目的地址表项时，需要广播
                    for intf in my_interfaces:
                        if fromIface!= intf.name:
                            log_info (f"Flooding packet {packet} to {intf.name}")
                            net.send_packet(intf, packet)
                else:
                    net.send_packet(floodjudge,packet)
                    log_info (f"Single packet {packet} to {floodjudge}")
                arp_table.print_arp()#打个arp表看看（输出到文件里）
                
    net.shutdown()

#Deploy
#server1 ping -c 1 server2
#client ping -c 1 server2
#server2 ping -c 1 server1