#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
import queue
#blaster负责发送包，接受ACK并维护滑动窗口

class Blaster:
    def __init__(self,net: switchyard.llnetbase.LLNetBase,blasteeIp, num,  length="100",senderWindow="5", timeout="3",recvTimeout="1"):
        self.net = net
        self.blasteeIp = blasteeIp
        self.num = int(num)
        self.length = int(length)
        self.senderWindow = int(senderWindow)
        self.timeout = int(timeout)/1000
        self.recvTimeout = int(recvTimeout)/1000

        self.LHS=1
        self.RHS=self.LHS+self.senderWindow-1
        self.time=time.time()
        self.ACKs=[False]*(self.num+1)
        self.payloads=[None]*(self.num+1)
        self.outport=self.net.interfaces()[0].name

        self.payload_init() #初始化payloads
        self.Retransmit_Queue=queue.Queue() #用于存储需要重传的包的序号

        # 统计量
        self.firstsendtime=1e20
        self.lastackdtime=0
        self.FirstSend=[True]*(self.num+1)
        self.Retransmit_Count=0
        self.CoarseTimeout_Count=0
        self.Throughput=0
        self.Goodput=0

    def payload_init(self):
        for i in range(1,self.num+1):
            self.payloads[i]=randint(0,2**32-1).to_bytes(self.length,'big')
            # 事先规定好每个包的数据部分

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        self.time=time.time() #更新计时器
        del packet[Ethernet]
        del packet[IPv4]
        del packet[UDP]
        #去除包头

        ACKnum=int.from_bytes(packet[0].to_bytes()[:4],'big')
        log_info("got a ACK packet with ACKnum: {}".format(ACKnum))
        #获取ACK包的序列号

        #遍历等待队列，如果ACKnum在等待队列中，就将其从等待队列中删除
        for i in range(self.Retransmit_Queue.qsize()):
            tmp=self.Retransmit_Queue.get()
            if tmp!=ACKnum:
                self.Retransmit_Queue.put(tmp)
            else:
                pass

        self.ACKs[ACKnum]=True
        # ACKnum对应的ACK标记为True

        while self.ACKs[self.LHS] and self.LHS<=self.RHS: #移动LHS
            self.LHS+=1
            self.time=time.time() #LHS更新，重置计时器
            if self.LHS==self.num+1:
                break
        # 如果LHS对应的ACK为True，就右移LHS，直到LHS对应的ACK为False或者LHS>RHS

        while self.RHS<self.num and self.RHS-self.LHS+1<self.senderWindow: #移动RHS
            self.RHS+=1
            self.Retransmit_Queue.put(self.RHS) #将RHS+1加入等待队列
        
        if self.LHS==self.num+1:
            log_info("All packets have been sent")
            self.lastackdtime=time.time()
            self.shutdown()

    def handle_no_packet(self):

        if time.time()-self.time>self.timeout: #超时了
            self.CoarseTimeout_Count+=1
            self.time=time.time() #更新计时器
            for NCKnum in range(self.LHS,self.RHS+1):
                if self.ACKs[NCKnum]: #在这个区间内，如果ACK已经收到，就不用再发了
                    continue
                self.Retransmit_Queue.put(NCKnum) #将需要重传的包的序号加入等待队列
            self.Retransmit_single_packet()
        else:
            self.Retransmit_single_packet()


    def Retransmit_single_packet(self):
        if self.Retransmit_Queue.qsize()!=0: #取队首，重发一个包
            current_num=self.Retransmit_Queue.get()
            SequencePart=RawPacketContents(current_num.to_bytes(4,'big')+self.length.to_bytes(2,'big'))
            Payload=RawPacketContents(self.payloads[current_num])
            #生成数据包的数据部分
            pkt=Packet()
            EthHeader=Ethernet()
            EthHeader.src="10:00:00:00:00:01"
            EthHeader.dst="40:00:00:00:00:01"
            IPv4Header=IPv4()
            IPv4Header.src='192.168.100.1'
            IPv4Header.dst=self.blasteeIp
            IPv4Header.protocol=IPProtocol.UDP
            IPv4Header.ttl=64
            UDPHeader=UDP()
            UDPHeader.src=514
            UDPHeader.dst=114
            pkt=EthHeader+IPv4Header+UDPHeader+SequencePart+Payload
            #生成数据包
            log_info(f"resending the packet:{int.from_bytes(SequencePart.to_bytes()[:4],'big')}")
            self.net.send_packet(self.outport,pkt)

            self.firstsendtime=min(self.firstsendtime,time.time())

            if self.FirstSend[current_num]==True:
                self.Goodput+=len(Payload)
                self.FirstSend[current_num]=False
            else:
                self.Retransmit_Count+=1
            self.Throughput+=len(Payload)
            return

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
            except NoPackets:
                log_info("Didn't receive anything")
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()
        self.info_print()

    def shutdown(self):
        self.net.shutdown()

    def info_print(self):
        log_info("----------------------")
        Total_TX_time=self.lastackdtime-self.firstsendtime
        log_info(f'Total TX time: {Total_TX_time}')
        log_info(f'Number of reTX: {self.Retransmit_Count}')
        log_info(f'Number of coarse TOs: {self.CoarseTimeout_Count}')
        log_info(f'Throughput: {self.Throughput/Total_TX_time}')
        log_info(f'Goodput: {self.Goodput/Total_TX_time}')

def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
