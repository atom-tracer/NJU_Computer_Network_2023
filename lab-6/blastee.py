#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
#blastee负责发送ACK包

class Blastee:
    def __init__(self,net: switchyard.llnetbase.LLNetBase,blasterIp,num):
        self.net = net
        self.blasterIp = blasterIp
        self.total_pkt_num = int(num) #总共要接受的包的数量
        self.current_num=0 #当前已经收到的包的数量
        self.pkt_received = set() #用集合来存储已经已经收到的包序列号，以此避免对重发包的重计数。

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        #log_info(f"I got a packet from {fromIface}")
        log_info(f"Pkt: {packet}")
        
        del packet[Ethernet]
        del packet[IPv4]
        del packet[UDP]
        #去除包头

        if int.from_bytes(packet[0].to_bytes()[:4],'big') not in self.pkt_received:
            self.pkt_received.add(int.from_bytes(packet[0].to_bytes()[:4],'big'))
            self.current_num+=1
            log_info(f"Received packet {int.from_bytes(packet[0].to_bytes()[:4],'big')}")
            #如果是第一次收到这个包，就把包的序列号加入集合，并且计数器加一

        pkt=Packet()
        EthHeader=Ethernet()
        EthHeader.src='20:00:00:00:00:01'
        EthHeader.dst='40:00:00:00:00:02'
        IPv4Header=IPv4()
        IPv4Header.src='192.168.200.1'
        IPv4Header.dst=self.blasterIp
        IPv4Header.protocol=IPProtocol.UDP
        IPv4Header.ttl=64
        UDPHeader=UDP()
        UDPHeader.src=114
        UDPHeader.dst=514
        #UDP随便设的
        pkt=EthHeader+IPv4Header+UDPHeader
        SequencePart=packet[0].to_bytes()[:4]
        pkt+=RawPacketContents(SequencePart)
        ACKPart=packet[0].to_bytes()[6:]+bytes(8)
        ACKPart=ACKPart[:8]
        pkt+=RawPacketContents(ACKPart)
        #构造ACK包
        log_info(f'Sending ACK packet {int.from_bytes(SequencePart,"big")}')
        self.net.send_packet(fromIface,pkt)

    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        while True:

            if self.current_num==self.total_pkt_num:
                log_info("All packets have been received.")
                self.shutdown() # 如果已经收到了所有的包，就关闭blastee
            else:
                pass

            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_info("No packets available in recv_packet")
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()