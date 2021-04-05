'''
myrouter.py 

Basic IPv4 router template (static routing) in Python, with ARP implemented.

Carleton CS 331, Fall 2020
Whitman CS 301, Fall 2021
'''
import pdb
from copy import deepcopy
import pandas as pd
import sys
import os
import time
from collections import namedtuple
from switchyard.lib.userlib import *
from ipaddress import IPv4Interface

class ArpPending(object):
    '''
    This class handles the mechanics of resending ARP requests, and determining
    when an ARP request should time out.
    
    :param str egress_dev: The interface on which to send the packet
    :param IPv4Address nexthop: The IP address of the next hop for the packet
    :param Packet pkt: The packet to send once the MAC address is determined
    '''
    def __init__(self, egress_dev, nexthop, pkt):
        self.egress_dev = egress_dev
        self.nexthop = nexthop
        self.pkt = pkt # packet object with Ethernet header stripped from head
        self.last_update = time.time()
        self.attempts = 0
    
    def can_try_again(self, timestamp):
        '''
        Returns True if we haven't timed out of ARP request attempts yet, 
        and False otherwise.
        '''
        if self.giveup(timestamp):
            return False
        if self.attempts == 0:
            return True
        if (timestamp - self.last_update) >= 1.0:
            return True
        return False

    def add_attempt(self):
        '''
        Accounting method: records the time, and increments the number of attempts,
        each time we re-attempt sending an ARP request.
        '''
        self.last_update = time.time()
        self.attempts += 1

    def giveup(self, timestamp):
        '''
        If we've used up all of our attempts and the timer's expired on the most 
        recent attempt, return True. We will send no more ARP requests.
        '''
        return self.attempts == 5 and (timestamp-self.last_update) >= 1.0

    def __str__(self):
        return "Packet to ARP: {} (nexthop: {}, egress: {}, attempts: {} last: {} now: {}".format(str(self.pkt), self.nexthop, self.egress_dev, self.attempts, self.last_update, time.time())

class Router(object):
    '''
    A Router takes in packets and sends them out the correct port.
    
    :param Net net: the Switchyard Net object
    '''
    def __init__(self, net):
        self.net = net
        self.interfaces = {}         # Maps interface names to interface objects (i.e. ports on router)
        self.mymacs = set()          # Set of MAC addresses for all interfaces
        self.myips = set()           # Set of IP addresses for all interfaces
        self.arptable = {}           # Maps IP addresses to MAC addresses
        self.layer2_forward_list = []# Stores ArpPending objects
        self.forwarding_table = None   # Change this if you want to!

        self.forwarding_table = pd.read_csv('forwarding_table.txt', sep=' ', names=['net_prefix', 'net_mask','next_hop', 'my_port_name'])
        self.forwarding_table['net'] = self.forwarding_table.apply(lambda x: 
            IPv4Network((x['net_prefix'], x['net_mask'])),axis=1)
        self.forwarding_table['next_hop'] = self.forwarding_table['next_hop'].apply(lambda x: IPv4Address(x))

        for intf in net.interfaces():
            self.interfaces[intf.name] = intf
            self.mymacs.add(intf.ethaddr)
            for ipaddr in intf.ipaddrs:
                self.arptable[ipaddr] = intf.ethaddr
                self.myips.add(ipaddr)
                self.forwarding_table = self.forwarding_table.append({'net_prefix':ipaddr,'net_mask':'255.255.255.255','next_hop':IPv4Address('0.0.0.0'),'my_port_name':intf.name,'net':ipaddr.network}, ignore_index=True)


        # *** You will need to add more code to this constructor ***

    def update_arp_table(self, ipaddr, macaddr):
        '''
        Associates the specified IP address with the specified MAC address 
        in the ARP table.
        '''
        log_info("Adding {} -> {} to ARP table".format(ipaddr, macaddr))
        self.arptable[ipaddr] = macaddr
        self.process_arp_pending()

    def arp_responder(self, dev, eth, arp):
        '''
        This is the part of the router that processes ARP requests and determines
        whether to update its ARP table and/or reply to the request
        '''
        # learn what we can from the arriving ARP packet
        if arp.senderprotoaddr != IPv4Address("0.0.0.0") and arp.senderhwaddr != EthAddr("ff:ff:ff:ff:ff:ff"):
            self.update_arp_table(arp.senderprotoaddr, arp.senderhwaddr)

        # if this is a request, reply if the targetprotoaddr is one of our addresses
        if arp.operation == ArpOperation.Request:
            log_debug("ARP request for {}".format(str(arp)))
            if arp.targetprotoaddr in self.myips: 
                log_debug("Got ARP for an IP address we know about")
                arpreply = create_ip_arp_reply(self.arptable[arp.targetprotoaddr], eth.src, arp.targetprotoaddr, arp.senderprotoaddr)
                self.update_arp_table(arp.sendpkt.payload.protosrc, pkt.payload.hwsrc)
                self.net.send_packet(dev, arpreply)

    def router_main(self):    
        while True:
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)

            except NoPackets:
                log_debug("Timeout waiting for packets")
                continue

            except Shutdown:
                return

            eth = pkt.get_header(Ethernet)

            if eth.ethertype == EtherType.ARP:
                log_debug("Received ARP packet: {}".format(str(pkt)))
                arp = pkt.get_header(Arp)
                self.arp_responder(dev, eth, arp)

            elif eth.ethertype == EtherType.IP:
                log_debug("Received IP packet: {}".format(str(pkt)))
                # TODO: process the IP packet and send out the correct interface
                # To send an ARP request and forward the packet:
                #   construct a new ArpPending object;
                #   add it to self.layer2_forward_list;
                #   call self.process_arp_pending().
                ip_hdr = pkt.get_header(IPv4)
                if ip_hdr.ttl > 0:
                    ip_hdr.ttl -= 1 #decrement the ip header ttl
                    #find next hop
                    dst = ip_hdr.dst
                    next_hop = self.find_most_precise(dst, 'next_hop')
                    #handle case on our net
                    if next_hop == IPv4Address('0.0.0.0'):
                        next_hop = dst
                    #strip ethernet header
                    eth_ind = pkt.get_header_index(Ethernet)
                    pkt_stripped = deepcopy(pkt)
                    del pkt_stripped[eth_ind]
                    #get the destination port interface
                    out_port = self.find_most_precise(dst, 'my_port_name')
                    #assemble arp pending
                    arppending = ArpPending(out_port, next_hop, pkt_stripped)
                    self.layer2_forward_list.append(arppending)
                    self.process_arp_pending()
                else:
                    #ideally respond with ICMP ttl expired, but not within scope of project
                    pass 

            else:
                log_warn("Received Non-IP packet that I don't know how to handle: {}".format(str(pkt)))

    def find_most_precise(self, dst, col):
        #this returns the most specific net containing dst.
        #It then accesses the col specified
        matched_nets = self.forwarding_table.loc[self.forwarding_table['net'].apply(lambda x: dst in x)]
        big_BoI = matched_nets['net'].apply(lambda x: x.prefixlen).argmax()
        most_precise_match = matched_nets.iloc[big_BoI][col]
        return most_precise_match

   # def find_most_precise(self, dst, col):
   #     ipaddrs = self.forwarding_table.loc[self.forwarding_table['type']=='addr']
   #     if len(ipaddrs) > 1:
   #         intermediate = ipaddrs.loc[ipaddrs['net'].apply(lambda x: dst == x)]
   #         matched_addr = (ipaddrs.loc[ipaddrs['net'].apply(lambda x: dst == x)]).iloc[0][col]
   #     else:
   #         nets = self.forwarding_table.loc[self.forwarding_table['type']=='net']
   #         matched_nets = nets.loc[nets['net'].apply(lambda x: dst in x)]
   #         big_BoI = matched_nets['net'].apply(lambda x: x.prefixlen).argmax()
   #         most_precise_match = matched_nets.iloc[big_BoI][col]
   #     return most_precise_match

    def layer2_forward(self, egress, mac_dst, pkt, xtype=EtherType.IPv4):
        #OUR METHOD!!!!!
        #note ttl is decremented coming in
        #pkt += Ethernet()
        pkt.prepend_header(Ethernet(dst=mac_dst, ethertype=xtype, src=self.interfaces[egress].ethaddr))
        eth_hdr = pkt.get_header(Ethernet)
        self.net.send_packet(egress, pkt)
        
    def process_arp_pending(self):
        '''
        Once an ArpPending object has been added to the layer 2 forwarding table, 
        this method handles the logistics of determining whether an ARP request 
        needs to be sent at all, and if so, handles the logistics of sending and 
        potentially resending the request.
        '''
        def _ipv4addr(intf):
            v4addrs = [i.ip for i in intf.ipaddrs if i.version == 4]
            return v4addrs[0]

        i = 0
        now = time.time()
        log_info("Processing outstanding packets to be ARPed at {}".format(now))
        newlist = []
        #~Debug
        counter = 0
        while len(self.layer2_forward_list):
            #~Debug
            log_info(f'i = {counter}')
            log_info(f'current layer2_forward_list = {self.layer2_forward_list}')
            thisarp = self.layer2_forward_list.pop(0)
            log_debug("Checking {}".format(str(thisarp)))
            log_debug("Current arp table: {}".format(str(self.arptable)))
            log_debug

            dstmac = None
            # Check: do we already know the MAC address? If so, go ahead and forward 
            log_debug(thisarp.nexthop)
            if thisarp.nexthop in self.arptable:
                dstmac = self.arptable[thisarp.nexthop]
                log_info("Already have MAC address for {}->{} - don't need to ARP".format(thisarp.nexthop, dstmac))
                # **NOTE: you will need to provide an implementation of layer2_forward
                self.layer2_forward(thisarp.egress_dev, dstmac, thisarp.pkt)
            else:
                # Not in ARP table, so send ARP request if we haven't timed out.
                if thisarp.can_try_again(now):
                    arpreq = self.make_arp_request(self.interfaces[thisarp.egress_dev].ethaddr,                                            _ipv4addr(self.interfaces[thisarp.egress_dev]), thisarp.nexthop)
                    p = Packet()
                    p += arpreq
                    log_info("ARPing for {} ({})".format(thisarp.nexthop, arpreq))
                    thisarp.add_attempt()

                    # **NOTE: you will need to provide an implementation of layer2_forward
                    self.layer2_forward(thisarp.egress_dev, "ff:ff:ff:ff:ff:ff",
                                        p, xtype=EtherType.ARP)
                    newlist.append(thisarp)
                    #~Debug
                    counter +=1
                elif thisarp.giveup(now):
                    log_warn("Giving up on ARPing {}".format(str(thisarp.nexthop)))

        self.layer2_forward_list = newlist

    def make_arp_request(self, hwsrc, ipsrc, ipdst):
        arp_req = Arp()
        arp_req.operation = ArpOperation.Request
        arp_req.senderprotoaddr = IPv4Address(ipsrc)
        arp_req.targetprotoaddr = IPv4Address(ipdst)
        arp_req.senderhwaddr = EthAddr(hwsrc)
        arp_req.targethwaddr = EthAddr("ff:ff:ff:ff:ff:ff")
        return arp_req


def main(net):
    '''
    Main entry point for router.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
