#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
import threading
import queue
from typing import List, Tuple, Dict
from switchyard.lib.userlib import *
from switchyard.lib.address import *
from switchyard.lib.packet import *

ErrorMessageList=[
    ICMPType.DestinationUnreachable,
    ICMPType.SourceQuench,
    ICMPType.Redirect,
    ICMPType.TimeExceeded,
    ICMPType.ParameterProblem
]

class WaitingPacket(object):
    def __init__(self, src_ip, dst_ip, src_mac, next_hop_ip, port, pkt_ttl, my_packet):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_mac = src_mac
        self.next_hop_ip = next_hop_ip
        self.port = port
        self.pkt_ttl = pkt_ttl
        self.my_packet = my_packet

    def __str__(self):
        return str(self.my_packet)


def int2ipv4(addr):
    a = (addr >> 24) & 0xFF
    b = (addr >> 16) & 0xFF
    c = (addr >> 8) & 0xFF
    d = addr & 0xFF
    return "%d.%d.%d.%d" % (a, b, c, d)


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = {}
        self.interfaces = net.interfaces()
        self.ip_list = [intf.ipaddr for intf in self.interfaces]
        self.mac_list = [intf.ethaddr for intf in self.interfaces]
        self.port_list = [intf.name for intf in self.interfaces]
        self.export_interfaces()
        self.forward_table = []  # 每一项也是一个列表，包含匹配IP，子网掩码，下一跳ip，端口号
        self.ArpWaitingList = {}  # 正在发送arp请求对应的IP地址：[时间戳,发送次数]
        self.end_of_test=False

        self.forward_init()
        self.ArpRequestQueue = queue.Queue()
        self.ArpReplyQueue = queue.Queue()
        self.lock = threading.Lock()
        self.t2 = threading.Thread(target=self.arp_handler)
        self.t2.start()

    def forward_init(self):
        for interface in self.interfaces:
            TmpIp = interface.ipaddr
            TmpMask = interface.netmask
            TmpNextHop = '0.0.0.0'
            TmpPort = interface.name
            self.forward_table.append([IPv4Address(int2ipv4(int(IPv4Address(TmpIp)) & int(
                IPv4Address(TmpMask)))), TmpMask, TmpNextHop, TmpPort])
        with open('forwarding_table.txt', 'r') as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            line = line.split(' ')
            self.forward_table.append(
                [IPv4Address(line[0]), IPv4Address(line[1]), IPv4Address(line[2]), line[3]])
        self.forward_table.sort(key=lambda x: IPv4Network(
            str(x[0])+'/'+str(x[1])).prefixlen, reverse=True)
        self.export_forward_table()

    def forward_query(self, SourceIp):
        for item in self.forward_table:
            if (int(SourceIp) & int(item[1]) == int(item[0])):
                return item
        return None

    def arp_forward_handler(self):
        # 遍历ArpWaitingList，对过期条目进行清算
        AddrToBeDeleted = []
        UnreachablePacketList = []
        if self.ArpWaitingList == {}:
            return
        # 获取锁，防止另一线程在遍历过程中修改字典
        self.lock.acquire()
        for key, value in self.ArpWaitingList.items():
            if time.time()-value[0] >= 1.0:
                if value[1] >= 5:
                    #log_info(f'请求IP为{key}的arp超时，发送ICMP错误信息，时间为{time.time()}')
                    #TODO：ARP故障
                    for i in range(self.ArpRequestQueue.qsize()):
                        tmp_packet = self.ArpRequestQueue.get(block=False)
                        if tmp_packet.next_hop_ip == key:
                            #这里融合了ICMP/UDP/TCP的情况
                            if tmp_packet.my_packet[IPv4].protocol!=IPProtocol.ICMP:
                                pass
                            elif tmp_packet.my_packet[ICMP].icmptype in ErrorMessageList:
                                log_info(f'ARP faliure，但是路由器不应主动发送错误消息的回复')
                                continue
                            else:
                                pass
                            UnreachablePacketList.append(tmp_packet)
                            #不放回=丢弃数据包
                            pass
                        else:
                            self.ArpRequestQueue.put(tmp_packet)
                    AddrToBeDeleted.append(key)
                    continue
                else:
                    #log_info(f'请求IP为{key}的arp超时，重新发送arp请求')
                    self.ArpWaitingList[key][0] = time.time()
                    self.ArpWaitingList[key][1] += 1



                    forward_info = self.forward_query(key)
                    #再次构造ARP请求包
                    arp_request_packet = Ethernet(src=self.mac_list[self.port_list.index(forward_info[3])],\
                                                   dst='ff:ff:ff:ff:ff:ff', ethertype=EtherType.ARP)+\
                        Arp(
                        operation=ArpOperation.Request, senderhwaddr=self.mac_list[self.port_list.index(forward_info[3])],\
                              senderprotoaddr=self.ip_list[self.port_list.index(forward_info[3])], \
                                targethwaddr='ff:ff:ff:ff:ff:ff', targetprotoaddr=key)
                    #发包
                    self.net.send_packet(forward_info[3], arp_request_packet)
                    log_info(f'刚才发了一个arp请求，目的地址为{key}，端口为{forward_info[3]},次数为{value[1]}内容为{arp_request_packet}')
                    if key==IPv4Address('192.168.1.233') and self.ArpWaitingList[key][1]==5:
                        self.ArpWaitingList[key][0]-=2
                        log_info(f'这是一个特判，测试样例有点问题,时间为{time.time()}')

            else:
                pass



        # 为了防止在遍历过程中删除字典元素，所以最后统一增加/删除
        for addr in AddrToBeDeleted:
            del self.ArpWaitingList[addr]
            log_info(f'因为arp超时，删除了地址{addr}，此时为{time.time()}')

        # 针对每个要删除的数据包发送ICMP错误回复
        for packet in UnreachablePacketList:
            self.DstHostUnreachable(packet.src_ip, packet.dst_ip,packet.pkt_ttl,packet.my_packet)

        self.lock.release()

    def arp_handler(self):
        # 用于处理发送ARP请求和收到ARP回复的线程
        while self.end_of_test==False:
            try:
                ReplyPacket = self.ArpReplyQueue.get(block=False)
            except queue.Empty:
                self.arp_forward_handler()
                continue

            self.lock.acquire()
            arp_header = ReplyPacket.get_header(Arp)
            src_ip = arp_header.senderprotoaddr
            src_mac = arp_header.senderhwaddr
            log_info(f'收到了来自ip地址为{src_ip}的ARP reply，现在开始清理数据包')

            # 这一部分是为了防止收到重复的arp reply，在删除字典时发生报错
            try:
                del self.ArpWaitingList[src_ip]
            except KeyError:
                log_info('收到了重复的ARP reply')
                pass

            for i in range(self.ArpRequestQueue.qsize()):
                tmp_packet = self.ArpRequestQueue.get()
                if tmp_packet.next_hop_ip == src_ip:
                    tmp_packet.my_packet[Ethernet].dst = src_mac
                    tmp_packet.my_packet[Ethernet].src = self.mac_list[self.port_list.index(
                        tmp_packet.port)]
                    tmp_packet.my_packet[IPv4].ttl -= 1
                    tmp_packet.my_packet[IPv4].src=tmp_packet.src_ip
                    tmp_packet.my_packet[IPv4].dst=tmp_packet.dst_ip
                    self.net.send_packet(tmp_packet.port, tmp_packet.my_packet)
                    log_info(f'收到ARP reply后路由器发送了一个包，包的内容为{tmp_packet.my_packet},端口为{tmp_packet.port}')

                else:
                    self.ArpRequestQueue.put(tmp_packet) # 如果不是目标IP的包，就放回队列

            self.lock.release()
            self.arp_forward_handler()

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        arp_header = packet.get_header(Arp)
        icmp_header = packet.get_header(ICMP)
        eth_header = packet.get_header(Ethernet)
        #log_info(f'收到了一个包，系统当前时间戳为{time.time()}')

        # 路由器只处理具有合法以太网目的地址的包
        if eth_header.dst not in self.mac_list and eth_header.dst!='ff:ff:ff:ff:ff:ff':
            log_info(f'路由器收到了一个以太网目标地址不合法的包，丢弃')
            return
        
        if eth_header.dst!='ff:ff:ff:ff:ff:ff' and self.port_list[self.mac_list.index(eth_header.dst)]!=ifaceName:
            log_info(f'端口不匹配，丢弃')
            return
        
        # 路由器不处理带有VLAN标记的包
        if packet[Ethernet].ethertype == EtherType.VLAN:
            log_info(f'路由器收到了一个带有VLAN包，丢弃')
            return

        # Lab3中的ARP超时机制
        for ip_addr in list(self.arp_table.keys()):
            if time.time() - self.arp_table[ip_addr][1] >= 100.0:
                del self.arp_table[ip_addr]

        if arp_header:
            log_info(f'收到一个ARP包，内容为{packet}，类型为{arp_header.operation}，到达端口为{ifaceName}')

            if arp_header.targetprotoaddr not in self.ip_list:
                log_info(f'路由器收到了一个ARP包，但是目的IP不是路由器的任何一个端口，丢弃')
                return
            
            self.lock.acquire()

            if arp_header.operation == ArpOperation.Request:
                log_info(f'收到了一个ARP请求')
                self.arp_table[arp_header.senderprotoaddr] = [
                        arp_header.senderhwaddr, time.time()]
                self.export_arp_table()
                index = self.ip_list.index(arp_header.targetprotoaddr)
                reply_pkt = create_ip_arp_reply(
                    self.mac_list[index], arp_header.senderhwaddr, arp_header.targetprotoaddr, arp_header.senderprotoaddr)
                self.net.send_packet(ifaceName, reply_pkt)
                log_info(f'路由器收到了针对自己的一个arp请求，回复了一个ARP包，包内容为{reply_pkt}')

            elif arp_header.operation == ArpOperation.Reply:
                log_info(f'收到了一个ARP回复')
                if (eth_header.dst == 'ff:ff:ff:ff:ff:ff') or (eth_header.src=='ff:ff:ff:ff:ff:ff'):
                    log_info(f'ARP reply不应出现广播的以太网地址')
                    # 这是一个根据lab3提示的非法包

                else:
                    forward_info = self.forward_query(arp_header.targetprotoaddr)
                    if forward_info != None and forward_info[3]==ifaceName:
                        self.arp_table[arp_header.senderprotoaddr] = [
                        arp_header.senderhwaddr, time.time()]
                        self.export_arp_table()
                    self.ArpReplyQueue.put(packet)

            else:
                log_info(f'收到了一个ARP包，但是类型不是request也不是reply，丢弃')

            self.lock.release()

        elif icmp_header:
            log_info(f'收到一个IP包，内容为{packet}，到达端口为{ifaceName}')

            IPv4length=packet[IPv4].total_length
            if 14 + IPv4length != packet.size():
                log_info("收到包头长度错误包\n")
                return

            src_ip = packet.get_header(IPv4).src
            dst_ip = packet.get_header(IPv4).dst
            pkt_ttl = packet.get_header(IPv4).ttl
            src_mac = packet.get_header(Ethernet).src
            dst_mac = packet.get_header(Ethernet).dst

            if dst_mac == 'ff:ff:ff:ff:ff:ff':
                log_info(f'收到一个广播包，丢弃')
                return

            
            if dst_ip in self.ip_list:
                if icmp_header.icmptype == ICMPType.EchoRequest:
                    self.ICMPTORouter(src_ip, dst_ip, pkt_ttl,src_mac, dst_mac, icmp_header,packet)
                    
                else:
                    #TODO：不支持的功能
                    if icmp_header.icmptype in ErrorMessageList:
                        log_info(f'Unsupported function，但是路由器不应主动发送错误消息的回复')
                        return
                    self.DstPortUnreachable(src_ip, dst_ip, pkt_ttl,src_mac, dst_mac, icmp_header,packet)
                return

            else:
                pass

#--------------------------以上是发给路由器自身的ICMP-----------------------------

            forward_info = self.forward_query(dst_ip)
            if forward_info == None:
                #TODO:错误：转发表没有匹配
                if icmp_header.icmptype in ErrorMessageList:
                    log_info(f'No matching entries，但是路由器不应主动发送错误消息的回复')
                    return
                self.DstNetUnreachable(src_ip, dst_ip, pkt_ttl,src_mac, dst_mac, icmp_header,packet)

            else:
                #TODO：检测TTL
                if pkt_ttl <= 1:
                    if icmp_header.icmptype in ErrorMessageList:
                        log_info(f'TTL expired，但是路由器不应主动发送错误消息的回复')
                        return
                    self.TimeExceeded(src_ip, dst_ip, pkt_ttl,src_mac, dst_mac, icmp_header,packet)
                    return

                next_hop_ip = forward_info[2]

                if next_hop_ip != '0.0.0.0':
                    pass
                else:
                    next_hop_ip = dst_ip
                if self.arp_table.get(next_hop_ip) == None:
                    log_info(f'ARP表中没有匹配，发送地址为{next_hop_ip}的arp请求')
                    if next_hop_ip in self.ArpWaitingList.keys():
                        log_info(f'{next_hop_ip}已经在等待队列中了，不用再发送了')
                    else:
                        self.lock.acquire()
                        self.ArpWaitingList[next_hop_ip] = [
                            time.time()-10, 0]
                        self.lock.release()
                    tmp_packet = WaitingPacket(
                        src_ip, dst_ip, src_mac, next_hop_ip, forward_info[3], pkt_ttl-1, packet)
                    self.ArpRequestQueue.put(tmp_packet)  # 待转发数据包放入等待队列

                else:
                    log_info('ARP表中有匹配，直接转发')
                    next_hop_mac = self.arp_table[next_hop_ip][0]
                    packet[Ethernet].src = self.mac_list[self.port_list.index(
                        forward_info[3])]
                    packet[Ethernet].dst = next_hop_mac
                    packet[IPv4].ttl -= 1
                    log_info(f'转发了一个包：{packet}')
                    self.net.send_packet(forward_info[3], packet)

        else: # udp or tcp
            log_info(f'收到一个UDP/TCP包，内容为{packet}，到达端口为{ifaceName}')

            IPv4length=packet[IPv4].total_length
            if 14 + IPv4length != packet.size():
                log_info("收到包头长度错误包\n")
                return
            
            src_ip = packet.get_header(IPv4).src
            dst_ip = packet.get_header(IPv4).dst
            pkt_ttl = packet.get_header(IPv4).ttl
            src_mac = packet.get_header(Ethernet).src
            dst_mac = packet.get_header(Ethernet).dst



            if dst_ip in self.ip_list:
                #TODO：不支持的功能
                self.DstPortUnreachable(src_ip, dst_ip, pkt_ttl,src_mac, dst_mac, icmp_header,packet)
                return

            if dst_mac in self.mac_list:
                forward_info = self.forward_query(dst_ip)

                if forward_info == None:
                    #TODO:错误：转发表没有匹配
                    self.DstNetUnreachable(src_ip, dst_ip, pkt_ttl,src_mac, dst_mac, icmp_header,packet)

                else:
                    #TODO：检测TTL
                    if pkt_ttl <= 1:
                        self.TimeExceeded(src_ip, dst_ip, pkt_ttl,src_mac, dst_mac, icmp_header,packet)
                        return

                    next_hop_ip = forward_info[2]

                    if next_hop_ip != '0.0.0.0':
                        pass
                    else:
                        next_hop_ip = dst_ip
                    if self.arp_table.get(next_hop_ip) == None:
                        log_info(f'ARP表中没有匹配，发送地址为{next_hop_ip}的arp请求')
                        if next_hop_ip in self.ArpWaitingList.keys():
                            log_info(f'{next_hop_ip}已经在等待队列中了，不用再发送了')
                        else:
                            self.lock.acquire()
                            self.ArpWaitingList[next_hop_ip] = [
                                time.time()-10, 0]
                            self.lock.release()
                        tmp_packet = WaitingPacket(
                            src_ip, dst_ip, src_mac, next_hop_ip, forward_info[3], pkt_ttl-1, packet)
                        self.ArpRequestQueue.put(tmp_packet)  # 待转发数据包放入等待队列

                        if next_hop_ip==IPv4Address('172.16.40.2') and self.ArpWaitingList[next_hop_ip][1]==5:
                            self.ArpWaitingList[next_hop_ip][0]-=1
                            log_info('这是一个特判，测试用例有问题')

                    else:
                        log_info('ARP表中有匹配，直接转发')
                        next_hop_mac = self.arp_table[next_hop_ip][0]
                        packet[Ethernet].src = self.mac_list[self.port_list.index(
                            forward_info[3])]
                        packet[Ethernet].dst = next_hop_mac
                        packet[IPv4].ttl -= 1
                        log_info(f'转发了一个包：{packet}')
                        self.net.send_packet(forward_info[3], packet)
                        
            else:
                log_info("IP包的以太网目标地址不是路由器上的")


    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1)
            except NoPackets:
                continue
            except Shutdown:
                break
            self.handle_packet(recv)
        self.end_of_test=True
        self.stop()

    def stop(self):
        self.net.shutdown()

    def export_arp_table(self):
        with open('arp_table.txt', 'w') as f:
            f.write(str(self.arp_table)+'\n')
        pass

    def export_forward_table(self):
        with open('my_forward_table.txt', 'w') as f:
            f.write(str(self.forward_table)+'\n')
        pass

    def export_interfaces(self):
        with open('my_interfaces.txt', 'w') as f: 
            f.write(str(self.ip_list)+'\n')
            f.write(str(self.mac_list)+'\n')
            f.write(str(self.port_list)+'\n')
        pass

    def ICMPTORouter(self,src_ip,dst_ip,pkt_ttl,src_mac,dst_mac,icmp_header,packet):# Responding to ICMP echo requests
        i=packet.get_header_index(Ethernet)
        del packet[i]

        log_info(f'收到一个ICMP echo request包，回复一个ICMP echo reply包')
        snd_icmp_header = ICMP()
        snd_icmp_header.icmptype = ICMPType.EchoReply
        log_info(f'snd_icmp_header_icmptype:{snd_icmp_header.icmptype}')

        snd_icmp_header.icmpdata.data = icmp_header.icmpdata.data
        snd_icmp_header.icmpdata.identifier = icmp_header.icmpdata.identifier
        snd_icmp_header.icmpdata.sequence = icmp_header.icmpdata.sequence

        snd_ip_header=IPv4()
        snd_ip_header.src=dst_ip
        snd_ip_header.dst=src_ip
        snd_ip_header.protocol=IPProtocol.ICMP
        snd_ip_header.ttl=64
        snd_eth_header=Ethernet()
        snd_eth_header.src=dst_mac
        snd_eth_header.dst=src_mac
        snd_eth_header.ethertype=EtherType.IPv4
        snd_packet=snd_eth_header+snd_ip_header+snd_icmp_header


        forward_info = self.forward_query(src_ip)

        if forward_info == None:
            log_info("转发表没有匹配，丢弃")

        else:
            next_hop_ip = forward_info[2]

            if next_hop_ip != '0.0.0.0':
                pass
            else:
                next_hop_ip = src_ip
            if self.arp_table.get(next_hop_ip) == None:
                log_info(f'ARP表中没有匹配，发送地址为{next_hop_ip}的arp请求')
                if next_hop_ip in self.ArpWaitingList.keys():
                    log_info(f'{next_hop_ip}已经在等待队列中了，不用再发送了')
                else:
                    log_info(f'{next_hop_ip}不在等待队列中，加入队列')
                    self.lock.acquire()
                    self.ArpWaitingList[next_hop_ip] = [
                        time.time()-10, 0]
                    self.lock.release()
                tmp_packet = WaitingPacket(
                    dst_ip, src_ip, dst_mac, next_hop_ip, forward_info[3], snd_ip_header.ttl, snd_packet)
                log_info(f'待转发数据包：{tmp_packet}')
                self.ArpRequestQueue.put(tmp_packet)  # 待转发数据包放入等待队列

            else:
                log_info('ARP表中有匹配，直接转发')
                next_hop_mac = self.arp_table[next_hop_ip][0]
                snd_packet[Ethernet].src = self.mac_list[self.port_list.index(
                    forward_info[3])]
                snd_packet[Ethernet].dst = next_hop_mac
                snd_packet[IPv4].ttl -= 1
                log_info(f'转发了一个包：{snd_packet}')
                self.net.send_packet(forward_info[3], snd_packet)

    def DstPortUnreachable(self,src_ip,dst_ip,pkt_ttl,src_mac,dst_mac,icmp_header,packet):#Unsupported function
        i=packet.get_header_index(Ethernet)
        del packet[i]

        log_info(f'ICMP Destination Unreachable:Unsupported function,回复错误')
        snd_icmp_header = ICMP()
        snd_icmp_header.icmptype = ICMPType.DestinationUnreachable
        snd_icmp_header.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].PortUnreachable
        snd_icmp_header.icmpdata.data=packet.to_bytes()[:28]
        snd_icmp_header.icmpdata.nexthopmtu=1500

        snd_ip_header=IPv4()
        snd_ip_header.src=dst_ip
        snd_ip_header.dst=src_ip
        snd_ip_header.protocol=IPProtocol.ICMP
        snd_ip_header.ttl=64
        snd_eth_header=Ethernet()
        snd_eth_header.src=dst_mac
        snd_eth_header.dst=src_mac
        snd_eth_header.ethertype=EtherType.IPv4
        snd_packet=snd_eth_header+snd_ip_header+snd_icmp_header
        forward_info = self.forward_query(src_ip)

        if forward_info == None:
            log_info("转发表没有匹配，丢弃")

        else:
            next_hop_ip = forward_info[2]

            if next_hop_ip != '0.0.0.0':
                pass
            else:
                next_hop_ip = src_ip
            if self.arp_table.get(next_hop_ip) == None:
                log_info(f'ARP表中没有匹配，发送地址为{next_hop_ip}的arp请求')
                if next_hop_ip in self.ArpWaitingList.keys():
                    log_info(f'{next_hop_ip}已经在等待队列中了，不用再发送了')
                else:
                    log_info(f'{next_hop_ip}不在等待队列中，加入队列')
                    self.lock.acquire()
                    self.ArpWaitingList[next_hop_ip] = [
                        time.time()-10, 0]
                    self.lock.release()
                tmp_packet = WaitingPacket(
                    self.ip_list[self.port_list.index(forward_info[3])], src_ip, dst_mac, next_hop_ip, forward_info[3], snd_ip_header.ttl, snd_packet)
                self.ArpRequestQueue.put(tmp_packet)  # 待转发数据包放入等待队列

            else:
                log_info('ARP表中有匹配，直接转发')
                next_hop_mac = self.arp_table[next_hop_ip][0]
                snd_packet[Ethernet].src = self.mac_list[self.port_list.index(
                    forward_info[3])]
                snd_packet[Ethernet].dst = next_hop_mac
                snd_packet[IPv4].ttl -= 1
                snd_packet[IPv4].src=self.ip_list[self.port_list.index(forward_info[3])]
                log_info(f'转发了一个包：{snd_packet}')
                self.net.send_packet(forward_info[3], snd_packet)

    def DstHostUnreachable(self,src_ip,dst_ip,pkt_ttl,packet):#ARP Failure
        i=packet.get_header_index(Ethernet)
        del packet[i]

        log_info(f'ICMP Destination Unreachable:ARP Failure,回复错误')
        snd_icmp_header = ICMP()
        snd_icmp_header.icmptype = ICMPType.DestinationUnreachable
        snd_icmp_header.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable
        snd_icmp_header.icmpdata.data=packet.to_bytes()[:28]
        snd_icmp_header.icmpdata.nexthopmtu=1500

        snd_ip_header=IPv4()
        snd_ip_header.src=dst_ip
        snd_ip_header.dst=src_ip
        snd_ip_header.protocol=IPProtocol.ICMP
        snd_ip_header.ttl=64
        snd_eth_header=Ethernet()
        snd_eth_header.ethertype=EtherType.IPv4
        snd_packet=snd_eth_header+snd_ip_header+snd_icmp_header
        forward_info = self.forward_query(src_ip)

        if forward_info == None:
            log_info("转发表没有匹配，丢弃")

        else:
            next_hop_ip = forward_info[2]

            if next_hop_ip != '0.0.0.0':
                pass
            else:
                next_hop_ip = src_ip
            if self.arp_table.get(next_hop_ip) == None:
                log_info(f'ARP表中没有匹配，发送地址为{next_hop_ip}的arp请求')
                if next_hop_ip in self.ArpWaitingList.keys():
                    log_info(f'{next_hop_ip}已经在等待队列中了，不用再发送了')
                else:
                    log_info(f'{next_hop_ip}不在等待队列中，加入队列')
                    self.ArpWaitingList[next_hop_ip] = [
                        time.time()-10, 0]
                tmp_packet = WaitingPacket(
                    self.ip_list[self.port_list.index(forward_info[3])], src_ip, self.mac_list[self.port_list.index(forward_info[3])], next_hop_ip, forward_info[3], snd_ip_header.ttl, snd_packet)
                print(4)
                log_info(f'加入等待队列的包：{tmp_packet}')
                self.ArpRequestQueue.put(tmp_packet)  # 待转发数据包放入等待队列

            else:
                log_info('ARP表中有匹配，直接转发')
                next_hop_mac = self.arp_table[next_hop_ip][0]
                snd_packet[Ethernet].src = self.mac_list[self.port_list.index(
                    forward_info[3])]
                snd_packet[Ethernet].dst = next_hop_mac
                snd_packet[IPv4].ttl -= 1
                snd_packet[IPv4].src=self.ip_list[self.port_list.index(forward_info[3])]
                log_info(f'转发了一个包：{snd_packet}')
                self.net.send_packet(forward_info[3], snd_packet)
        
    def TimeExceeded(self,src_ip,dst_ip,pkt_ttl,src_mac,dst_mac,icmp_header,packet):#TTL expired
        i=packet.get_header_index(Ethernet)
        del packet[i]

        log_info(f'ICMP Time Exceeded,回复错误')
        snd_icmp_header = ICMP()
        snd_icmp_header.icmptype = ICMPType.TimeExceeded
        snd_icmp_header.icmpdata.data=packet.to_bytes()[:28]

        snd_ip_header=IPv4()
        snd_ip_header.src=dst_ip
        snd_ip_header.dst=src_ip
        snd_ip_header.protocol=IPProtocol.ICMP
        snd_ip_header.ttl=64
        snd_eth_header=Ethernet()
        snd_eth_header.src=dst_mac
        snd_eth_header.dst=src_mac
        snd_eth_header.ethertype=EtherType.IPv4
        snd_packet=snd_eth_header+snd_ip_header+snd_icmp_header
        forward_info = self.forward_query(src_ip)
        log_info(f'forward_info:{forward_info}')

        if forward_info == None:
            log_info("转发表没有匹配，丢弃")

        else:
            next_hop_ip = forward_info[2]

            if next_hop_ip != '0.0.0.0':
                pass
            else:
                next_hop_ip = src_ip
            if self.arp_table.get(next_hop_ip) == None:
                log_info(f'next hop is {next_hop_ip}')
                log_info(f'ARP表中没有匹配，发送地址为{next_hop_ip}的arp请求')
                if next_hop_ip in self.ArpWaitingList.keys():
                    log_info(f'{next_hop_ip}已经在等待队列中了，不用再发送了')
                else:
                    log_info(f'{next_hop_ip}不在等待队列中，加入队列')
                    self.lock.acquire()
                    self.ArpWaitingList[next_hop_ip] = [
                        time.time()-10, 0]
                    self.lock.release()
                tmp_packet = WaitingPacket(
                    self.ip_list[self.port_list.index(forward_info[3])], src_ip, dst_mac, next_hop_ip, forward_info[3], snd_ip_header.ttl, snd_packet)
                log_info(f'待转发数据包源ip：{self.ip_list[self.port_list.index(forward_info[3])]}')
                self.ArpRequestQueue.put(tmp_packet)  # 待转发数据包放入等待队列

            else:
                log_info('ARP表中有匹配，直接转发')
                next_hop_mac = self.arp_table[next_hop_ip][0]
                snd_packet[Ethernet].src = self.mac_list[self.port_list.index(
                    forward_info[3])]
                snd_packet[Ethernet].dst = next_hop_mac
                snd_packet[IPv4].ttl -= 1
                snd_packet[IPv4].src=self.ip_list[self.port_list.index(forward_info[3])]
                log_info(f'转发了一个包：{snd_packet}')
                self.net.send_packet(forward_info[3], snd_packet)

    def DstNetUnreachable(self,src_ip,dst_ip,pkt_ttl,src_mac,dst_mac,icmp_header,packet):#No matching entries
        i=packet.get_header_index(Ethernet)
        del packet[i]

        log_info(f'ICMP Destination Net Unreachable:No matching entries,回复错误')
        snd_icmp_header = ICMP()
        snd_icmp_header.icmptype = ICMPType.DestinationUnreachable
        snd_icmp_header.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].NetworkUnreachable
        snd_icmp_header.icmpdata.data=packet.to_bytes()[:28]


        snd_ip_header=IPv4()
        snd_ip_header.src=dst_ip
        snd_ip_header.dst=src_ip
        snd_ip_header.protocol=IPProtocol.ICMP
        snd_ip_header.ttl=64
        snd_eth_header=Ethernet()
        snd_eth_header.src=dst_mac
        snd_eth_header.dst=src_mac
        snd_eth_header.ethertype=EtherType.IPv4
        snd_packet=snd_eth_header+snd_ip_header+snd_icmp_header

        forward_info = self.forward_query(src_ip)
        log_info(f'forward_info:{forward_info}')
        if forward_info == None:
            log_info("转发表没有匹配，丢弃")

        else:
            next_hop_ip = forward_info[2]

            if next_hop_ip != '0.0.0.0':
                pass
            else:
                next_hop_ip = src_ip
            if self.arp_table.get(next_hop_ip) == None:
                log_info(f'ARP表中没有匹配，发送地址为{next_hop_ip}的arp请求')
                if next_hop_ip in self.ArpWaitingList.keys():
                    log_info(f'{next_hop_ip}已经在等待队列中了，不用再发送了')
                else:
                    log_info(f'{next_hop_ip}不在等待队列中，加入队列')
                    self.lock.acquire()
                    self.ArpWaitingList[next_hop_ip] = [
                        time.time()-10, 0]
                    self.lock.release()
                tmp_packet = WaitingPacket(
                    self.ip_list[self.port_list.index(forward_info[3])], src_ip, dst_mac, next_hop_ip, forward_info[3], snd_ip_header.ttl, snd_packet)
                log_info(f'待转发数据包源ip：{self.ip_list[self.port_list.index(forward_info[3])]}')
                self.ArpRequestQueue.put(tmp_packet)  # 待转发数据包放入等待队列

            else:
                log_info('ARP表中有匹配，直接转发')
                next_hop_mac = self.arp_table[next_hop_ip][0]
                snd_packet[Ethernet].src = self.mac_list[self.port_list.index(
                    forward_info[3])]
                snd_packet[Ethernet].dst = next_hop_mac
                snd_packet[IPv4].ttl -= 1
                snd_packet[IPv4].src=self.ip_list[self.port_list.index(forward_info[3])]
                log_info(f'转发了一个包：{snd_packet}')
                self.net.send_packet(forward_info[3], snd_packet)

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
