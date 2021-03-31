#!/usr/bin/env python

import copy
from switchyard.lib.userlib import *

def mk_arpresp(arpreqpkt, hwsrc, arphwsrc=None, arphwdst=None):
    # hwdst (hwsrc), ipsrc (ipdst), ipdst (ipsrc) come from arpreq

    if arphwsrc is None:
        arphwsrc = hwsrc
    if arphwdst is None:
        arphwdst = arpreqpkt.get_header(Arp).senderhwaddr
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = arpreqpkt.get_header(Arp).senderhwaddr
    ether.ethertype = EtherType.ARP
    arp_reply = Arp()
    arp_reply.operation = ArpOperation.Reply
    arp_reply.senderprotoaddr = IPv4Address(arpreqpkt.get_header(Arp).targetprotoaddr)
    arp_reply.targetprotoaddr = IPv4Address(arpreqpkt.get_header(Arp).senderprotoaddr)
    arp_reply.senderhwaddr = EthAddr(arphwsrc)
    arp_reply.targethwaddr = EthAddr(arphwdst)
    return ether + arp_reply


def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64, payload=''):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPv4Address(ipsrc)
    ippkt.dst = IPv4Address(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    if reply:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoRequest
    icmppkt.icmpdata.sequence = 42
    icmppkt.icmpdata.data = payload
    return ether + ippkt + icmppkt 

def forwarding_arp_tests():
    s = TestScenario("IP forwarding and ARP requester tests")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1/24')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1/16')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1/30')
    s.add_file('forwarding_table.txt', '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
10.100.0.0 255.255.0.0 172.16.42.2 router-eth2''')

    reqpkt = mk_ping("20:00:00:00:00:01", "10:00:00:00:00:01", '192.168.1.100','172.16.42.2', ttl=64)
    reqpkt2 = copy.deepcopy(reqpkt)
    reqpkt2.get_header(Ethernet).src = EthAddr("10:00:00:00:00:03")
    reqpkt2.get_header(Ethernet).dst = EthAddr("30:00:00:00:00:01")

    arpreq = create_ip_arp_request("10:00:00:00:00:03", "172.16.42.1", "172.16.42.2")
    arpresp = mk_arpresp(arpreq, "30:00:00:00:00:01") # , "10:00:00:00:00:03", "172.16.42.2", "172.16.42.1")

    arpreq2 = create_ip_arp_request("10:00:00:00:00:01", "192.168.1.1", "192.168.1.100")
    arpresp2 = mk_arpresp(arpreq2, "20:00:00:00:00:01") # , "10:00:00:00:00:01", "192.168.1.100", "192.168.1.1")

    resppkt = mk_ping("30:00:00:00:00:01", "10:00:00:00:00:03", '172.16.42.2', '192.168.1.100', reply=True, ttl=64)
    resppkt2 = copy.deepcopy(resppkt)
    resppkt2.get_header(Ethernet).src = EthAddr("10:00:00:00:00:01")
    resppkt2.get_header(Ethernet).dst = EthAddr("20:00:00:00:00:01")

    reqpkt3a = copy.deepcopy(reqpkt)
    reqpkt3b = copy.deepcopy(reqpkt2)
    resppkt3a = copy.deepcopy(resppkt)
    resppkt3b = copy.deepcopy(resppkt2)

    ttlmatcher = '''lambda pkt: pkt.get_header(IPv4).ttl == 63'''

    s.expect(PacketInputEvent("router-eth0", reqpkt, display=IPv4), 
             "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")
    s.expect(PacketOutputEvent("router-eth2", arpreq, display=Arp),
             "Router should send ARP request for 172.16.42.2 out router-eth2 interface")
    s.expect(PacketInputEvent("router-eth2", arpresp, display=Arp),
             "Router should receive ARP response for 172.16.42.2 on router-eth2 interface")
    s.expect(PacketOutputEvent("router-eth2", reqpkt2, display=IPv4, exact=False, predicates=[ttlmatcher]),
             "IP packet should be forwarded to 172.16.42.2 out router-eth2")
    s.expect(PacketInputEvent("router-eth2", resppkt, display=IPv4),
             "IP packet to be forwarded to 192.168.1.100 should arrive on router-eth2")
    s.expect(PacketOutputEvent("router-eth0", arpreq2, display=Arp),
             "Router should send ARP request for 192.168.1.100 out router-eth0")
    s.expect(PacketInputEvent("router-eth0", arpresp2, display=Arp),
             "Router should receive ARP response for 192.168.1.100 on router-eth0")
    s.expect(PacketOutputEvent("router-eth0", resppkt2, display=IPv4, exact=False, predicates=[ttlmatcher]),
             "IP packet should be forwarded to 192.168.1.100 out router-eth0")

    s.expect(PacketInputEvent("router-eth0", reqpkt3a, display=IPv4),
             "Another IP packet for 172.16.42.2 should arrive on router-eth0")
    s.expect(PacketOutputEvent("router-eth2", reqpkt3b, display=IPv4, exact=False, predicates=[ttlmatcher]),
             "IP packet should be forwarded to 172.16.42.2 out router-eth2 (no ARP request should be necessary since the information from a recent ARP request should be cached)")
    s.expect(PacketInputEvent("router-eth2", resppkt3a, display=IPv4),
             "IP packet to be forwarded to 192.168.1.100 should arrive on router-eth2")
    s.expect(PacketOutputEvent("router-eth0", resppkt3b, display=IPv4, exact=False, predicates=[ttlmatcher]),
             "IP packet should be forwarded to 192.168.1.100 out router-eth0 (again, no ARP request should be necessary since the information from a recent ARP request should be cached)")

    # PING for 172.16.64.35 should go out router-eth1 with next hop of 10.10.1.254
    otroping = mk_ping("40:00:00:00:00:11", "10:00:00:00:00:03", '10.100.1.55', '172.16.64.35', reply=False, ttl=32)
    otroarp = create_ip_arp_request("10:00:00:00:00:02", "10.10.0.1", "10.10.1.254")
    otroarpresponse = mk_arpresp(otroarp, "11:22:33:44:55:66")

    s.expect(PacketInputEvent("router-eth2", otroping, display=IPv4),
        "An IP packet from 10.100.1.55 to 172.16.64.35 should arrive on router-eth1")
    s.expect(PacketOutputEvent("router-eth1", otroarp, display=Arp),
        "Router should send an ARP request for 10.10.1.254 on router-eth1")
    s.expect(PacketInputTimeoutEvent(1.5),
        "Application should try to receive a packet, but then timeout")
    # slow ARP response!
    s.expect(PacketOutputEvent("router-eth1", otroarp, display=Arp),
        "Router should send another an ARP request for 10.10.1.254 on router-eth1 because of a slow response")
    s.expect(PacketInputEvent("router-eth1", otroarpresponse, display=Arp),
        "Router should receive an ARP response for 10.10.1.254 on router-eth1")

    ttlmatcher32 = '''lambda pkt: pkt.get_header(IPv4).ttl == 31'''
    otroping2 = copy.deepcopy(otroping)
    otroping2.get_header(Ethernet).src = EthAddr("10:00:00:00:00:02")
    otroping2.get_header(Ethernet)  .dst = EthAddr("11:22:33:44:55:66")
    s.expect(PacketOutputEvent("router-eth1", otroping2, display=IPv4, exact=False, predicates=[ttlmatcher32]),
        "IP packet destined to 172.16.64.35 should be forwarded on router-eth1")
    # no response for PING --- that's ok! 

    # PING for 10.200.1.1 -> no matching forwarding table entry :-(
    noforwardingmatch = mk_ping("ab:cd:ef:ab:cd:ef", "10:00:00:00:00:01", "192.168.1.239", "10.200.1.1")
    s.expect(PacketInputEvent("router-eth0", noforwardingmatch, display=IPv4),
        "An IP packet from 192.168.1.239 for 10.200.1.1 should arrive on router-eth0.  No forwarding table entry should match.")

    # PING for 10.10.50.250 should go out router-eth1: assume that ARP fails
    lastping = mk_ping("ab:cd:ef:ab:cd:ef", "10:00:00:00:00:01", "192.168.1.239", "10.10.50.250")
    lastarp = create_ip_arp_request("10:00:00:00:00:02", "10.10.0.1", "10.10.50.250")
    s.expect(PacketInputEvent("router-eth0", lastping, display=IPv4),
        "An IP packet from 192.168.1.239 for 10.10.50.250 should arrive on router-eth0.")
    s.expect(PacketOutputEvent("router-eth1", lastarp, display=Arp),
        "Router should send an ARP request for 10.10.50.250 on router-eth1")
    s.expect(PacketInputTimeoutEvent(1.5),
        "Router should try to receive a packet (ARP response), but then timeout")
    s.expect(PacketOutputEvent("router-eth1", lastarp, display=Arp),
        "Router should send an ARP request for 10.10.50.250 on router-eth1")
    s.expect(PacketInputTimeoutEvent(1.5),
        "Router should try to receive a packet (ARP response), but then timeout")
    s.expect(PacketOutputEvent("router-eth1", lastarp, display=Arp),
        "Router should send an ARP request for 10.10.50.250 on router-eth1")
    s.expect(PacketInputTimeoutEvent(1.5),
        "Router should try to receive a packet (ARP response), but then timeout")
    s.expect(PacketOutputEvent("router-eth1", lastarp, display=Arp),
        "Router should send an ARP request for 10.10.50.250 on router-eth1")
    s.expect(PacketInputTimeoutEvent(1.5),
        "Router should try to receive a packet (ARP response), but then timeout")
    s.expect(PacketOutputEvent("router-eth1", lastarp, display=Arp),
        "Router should send an ARP request for 10.10.50.250 on router-eth1")
    s.expect(PacketInputTimeoutEvent(1.5),
        "Router should try to receive a packet (ARP response), but then timeout")
    s.expect(PacketInputTimeoutEvent(1.5),
        "Router should try to receive a packet (ARP response), but then timeout")

    return s

scenario = forwarding_arp_tests()
