from switchyard.lib.userlib import *


def new_packet(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def test_hub():
    s = TestScenario("hub tests")
    s.add_interface('eth1', '60:00:00:00:00:01')
    s.add_interface('eth2', '60:00:00:00:00:02')
    s.add_interface('eth3', '60:00:00:00:00:03')
    s.add_interface('eth4', '60:00:00:00:00:04')
    s.add_interface('eth5', '60:00:00:00:00:05')

    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = new_packet(
        "10:00:00:00:00:01",
        "ff:ff:ff:ff:ff:ff",
        "172.16.42.2",
        "255.255.255.255"
    )
    s.expect(
        PacketInputEvent("eth1", testpkt, display=Ethernet),
        ("An Ethernet frame with a broadcast destination address "
         "should arrive on eth2")
    )
    s.expect(
        PacketOutputEvent("eth2", testpkt, "eth3", testpkt, "eth4", testpkt,"eth5", testpkt, display=Ethernet),
        ("The Ethernet frame with a broadcast destination address should be "
         "forwarded out ports eth2 - eth5")
    )

    # test case 2: a frame with any unicast address except one assigned to hub
    # interface should be sent out all ports except ingress
    
    reqpkt = new_packet(
        "50:00:00:00:00:01",
        "20:00:00:00:00:01",
        '172.16.42.2',
        '192.168.1.100',
        reply=True
    )
    s.expect(
        PacketInputEvent("eth5", reqpkt, display=Ethernet),
        ("An Ethernet frame from 50:00:00:00:00:02 to 20:00:00:00:00:01 "
         "should arrive on eth5")
    )
    s.expect(
        PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, "eth3", reqpkt,"eth4", reqpkt, display=Ethernet),
        ("Ethernet frame destined to 20:00:00:00:00:01 should be flooded out"
         "eth0 and eth2")
    )

    resppkt = new_packet(
        "20:00:00:00:00:01",
        "50:00:00:00:00:01",
        '192.168.1.100',
        '172.16.42.2',
        reply=True
    )
    s.expect(
        PacketInputEvent("eth2", resppkt, display=Ethernet),
        ("An Ethernet frame from 50:00:00:00:00:02 to 20:00:00:00:00:01 "
         "should arrive on eth5")
    )
    s.expect(
        PacketOutputEvent("eth1", resppkt, "eth3", resppkt, "eth4", resppkt,"eth5", resppkt,display=Ethernet),
        ("Ethernet frame destined to 20:00:00:00:00:01 should be flooded out"
         "eth0 and eth2")
    )

    # test case 3: a frame with dest address of one of the interfaces should
    # result in nothing happening
    reqpkt = new_packet(
        "30:00:00:00:00:01",
        "60:00:00:00:00:04",
        '192.168.1.100',
        '172.16.42.2'
    )
    s.expect(
        PacketInputEvent("eth3", reqpkt, display=Ethernet),
        ("An Ethernet frame should arrive on eth3 with destination address "
         "the same as eth4's MAC address")
    )
    s.expect(
        PacketInputTimeoutEvent(1.0),
        ("The hub should not do anything in response to a frame arriving with"
         " a destination address referring to the hub itself.")
    )
    return s


scenario = test_hub()
