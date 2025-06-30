# L3Firewall.py (Final version for Python 2.7 compatibility and Port Security)

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
import csv
import argparse
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

log = core.getLogger()
priority = 50000

l2config = "l2firewall.config"
l3config = "l3firewall.config"

# --- Port Security Additions ---
port_security_table = {} # Stores {MAC_ADDRESS: IP_ADDRESS}
blocked_macs = set() # Stores MACs that have been blocked due to spoofing
# --- End Port Security Additions ---


class Firewall (EventMixin):

    def __init__ (self,l2config,l3config):
        self.listenTo(core.openflow)
        self.disbaled_MAC_pair = [] # Stores a tuple of MAC pair which will be installed into the flow table of each switch.
        self.fwconfig = list() # This variable seems unused, keeping it as is from original.

        # Read the CSV file for L2 firewall rules
        if l2config == "":
            l2config="l2firewall.config"
            
        if l3config == "":
            l3config="l3firewall.config" 
        with open(l2config, 'r') as rules: # Changed 'rb' to 'r' for text mode
            csvreader = csv.DictReader(rules)
            for line in csvreader:
                if line['mac_0'] != 'any':
                    mac_0 = EthAddr(line['mac_0'])
                else:
                    mac_0 = None

                if line['mac_1'] != 'any':
                    mac_1 = EthAddr(line['mac_1'])
                else:
                    mac_1 = None
                self.disbaled_MAC_pair.append((mac_0,mac_1))

        # Read the CSV file for L3 firewall rules
        # Load rules into a list so they can be iterated multiple times
        with open(l3config, 'r') as csvfile: # Changed to 'r' for text mode, consistent
            log.debug("Reading L3 firewall config file !")
            # self.rules is now a list, not a DictReader iterator
            self.l3_rules_list = list(csv.DictReader(csvfile)) # Store as a list
            for row in self.l3_rules_list: # Iterate the list for initial debug
                log.debug("Saving individual rule parameters in rule dict ! %s" % (row,)) # Python 2 compatible formatting

        log.debug("Enabling Firewall Module")

    def replyToARP(self, packet, match, event):
        r = arp()
        r.opcode = arp.REPLY
        r.hwdst = match.dl_src
        r.protosrc = match.nw_dst
        r.protodst = match.nw_src
        r.hwsrc = match.dl_dst
        e = ethernet(type=packet.ARP_TYPE, src = r.hwsrc, dst=r.hwdst)
        e.set_payload(r)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = event.port
        event.connection.send(msg)

    def allowOther(self,event):
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        action = of.ofp_action_output(port = of.OFPP_NORMAL)
        msg.actions.append(action)
        msg.priority = 1 # Lower priority
        event.connection.send(msg)

    # MODIFIED: installFlow function to handle explicit drops and handle None values
    def installFlow(self, event, offset, srcmac, dstmac, srcip, dstip, sport, dport, nwproto, drop_packet=False):
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        
        if srcip is not None:
            match.nw_src = IPAddr(srcip)
        if dstip is not None:
            match.nw_dst = IPAddr(dstip)    
        
        if nwproto is not None:
            match.nw_proto = int(nwproto)
        
        if srcmac is not None:
            match.dl_src = srcmac
        if dstmac is not None:
            match.dl_dst = dstmac
        
        # Check if sport and dport are not None before converting to int
        if sport is not None:
            match.tp_src = int(sport)
        if dport is not None:
            match.tp_dst = int(dport)
            
        match.dl_type = pkt.ethernet.IP_TYPE
        msg.match = match
        msg.hard_timeout = 0
        msg.idle_timeout = 200
        msg.priority = priority + offset        
        
        # Action based on drop_packet flag
        if drop_packet:
            # For OpenFlow 1.0, omitting actions or using OFPP_NONE drops the packet
            # msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE)) # Explicit drop, optional
            log.debug("Installing DROP flow for match: %s" % (match,)) # Python 2 compatible
        else:
            # If not dropping, add a forwarding action (e.g., normal forwarding)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
            log.debug("Installing FORWARD flow for match: %s" % (match,)) # Python 2 compatible

        event.connection.send(msg)

    def replyToIP(self, packet, match, event, fwconfig_list): # Renamed fwconfig to fwconfig_list for clarity
        # Iterate over the loaded L3 rules (which is now a list)
        for row in fwconfig_list: 
            prio = row.get('priority')
            srcmac_rule = row.get('src_mac')
            dstmac_rule = row.get('dst_mac')
            s_ip_rule = row.get('src_ip')
            d_ip_rule = row.get('dst_ip')
            s_port_rule = row.get('src_port')
            d_port_rule = row.get('dst_port')
            nw_proto_rule = row.get('nw_proto')
            
            log.debug("Applying L3 firewall rule from config...")
            
            srcmac1 = EthAddr(srcmac_rule) if srcmac_rule and srcmac_rule != 'any' else None
            dstmac1 = EthAddr(dstmac_rule) if dstmac_rule and dstmac_rule != 'any' else None
            s_ip1 = s_ip_rule if s_ip_rule and s_ip_rule != 'any' else None
            d_ip1 = d_ip_rule if d_ip_rule and d_ip_rule != 'any' else None
            s_port1 = int(s_port_rule) if s_port_rule and s_port_rule != 'any' else None
            d_port1 = int(d_port_rule) if d_port_rule and d_port_rule != 'any' else None
            prio1 = int(prio) if prio is not None and prio != 'any' else priority # Corrected check for prio

            nw_proto1 = None
            if nw_proto_rule == "tcp":
                nw_proto1 = pkt.ipv4.TCP_PROTOCOL
            elif nw_proto_rule == "icmp":
                nw_proto1 = pkt.ipv4.ICMP_PROTOCOL
                s_port1 = None
                d_port1 = None
            elif nw_proto_rule == "udp":
                nw_proto1 = pkt.ipv4.UDP_PROTOCOL
            else:
                log.debug("PROTOCOL field is mandatory in L3 config, Choose between ICMP, TCP, UDP or set to 'any'")
                continue # Skip this rule if protocol is not valid

            # Call installFlow with drop_packet=True to install blocking rules
            self.installFlow(event, prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1, drop_packet=True)
        
        # After attempting to install L3 specific rules, allow other traffic to flow normally.
        # This will be overridden by higher priority rules (like our port security or L2 rules).
        self.allowOther(event)


    def _handle_ConnectionUp (self, event):
        self.connection = event.connection

        # Install L2 blocking rules from l2firewall.config
        for (source, destination) in self.disbaled_MAC_pair:
            print "Installing L2 block rule: %s -> %s" % (source, destination) # Python 2 compatible print
            message = of.ofp_flow_mod()
            match = of.ofp_match()
            if source:
                match.dl_src = source
            if destination:
                match.dl_dst = destination
            message.priority = 65535 # Highest priority for fixed L2 blocking rules
            message.match = match      
            # No actions means drop the packet implicitly for OpenFlow 1.0
            event.connection.send(message)

        log.debug("L2 Firewall rules installed on %s", dpidToStr(event.dpid))
        
        # Ensure a low-priority allow-all rule is installed to cover unhandled traffic
        self.allowOther(event)

    def _handle_PacketIn(self, event):

        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        match = of.ofp_match.from_packet(packet)

        # Handle ARP requests - Important for network discovery and host resolution
        if match.dl_type == packet.ARP_TYPE and match.nw_proto == arp.REQUEST:
            self.replyToARP(packet, match, event)
            return

        # --- Port Security Logic (applies to IP packets) ---
        if match.dl_type == packet.IP_TYPE:
            ip_packet = packet.payload
            
            src_mac = packet.src
            src_ip = ip_packet.srcip

            log.debug("PacketIn from %s (IP: %s) on port %s" % (src_mac, src_ip, event.port)) # Python 2 compatible

            # 1. Check if this MAC is already permanently blocked due to a previous spoofing attempt
            if src_mac in blocked_macs:
                log.info("Blocked MAC %s (IP: %s) attempted to send traffic. Dropping packet." % (src_mac, src_ip)) # Python 2 compatible
                return # Drop the packet by not processing it further

            # 2. Implement Port Security Pseudo-code:
            if src_mac not in port_security_table:
                # First time seeing this MAC, record its associated IP
                log.info("Port Security: New MAC-IP mapping established: %s <--> %s" % (src_mac, src_ip)) # Python 2 compatible
                port_security_table[src_mac] = src_ip
            else:
                # MAC is known, check if the IP is consistent
                expected_ip = port_security_table[src_mac]
                if src_ip != expected_ip:
                    # Port security violation detected!
                    log.warning("Port Security VIOLATION: MAC %s (expected IP: %s) is spoofing IP %s. Blocking this MAC permanently." % (src_mac, expected_ip, src_ip)) # Python 2 compatible
                    
                    blocked_macs.add(src_mac) # Add MAC to `blocked_macs`

                    # Install a flow rule to block all future traffic from this source MAC
                    msg = of.ofp_flow_mod()
                    msg.match.dl_src = src_mac
                    # Use a very high priority to ensure it overrides everything else
                    msg.priority = of.OFP_DEFAULT_PRIORITY + 20000 
                    msg.idle_timeout = 0 # Don't expire
                    msg.hard_timeout = 0 # Don't expire
                    # No actions means drop the packet implicitly for OpenFlow 1.0
                    event.connection.send(msg)

                    log.info("Port Security: Installed flow rule to block ALL traffic from malicious MAC: %s." % (src_mac,)) # Python 2 compatible
                    return # Drop the current spoofed packet by not processing it further

            # If the packet passed port security, proceed with other IP-related firewall rules/forwarding
            self.replyToIP(packet, match, event, self.l3_rules_list)


def launch (l2config="l2firewall.config",l3config="l3firewall.config"):
    core.registerNew(Firewall,l2config,l3config)
