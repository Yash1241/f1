# L3Firewall.py (Corrected for OFPAT_DROP error and ready for Port Security)

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

# --- Port Security Additions (from previous discussion) ---
port_security_table = {}
blocked_macs = set()
# --- End Port Security Additions ---


class Firewall (EventMixin):

    def __init__ (self,l2config,l3config):
        self.listenTo(core.openflow)
        self.disbaled_MAC_pair = [] # Store a tuple of MAC pair which will be installed into the flow table of each switch.
        self.fwconfig = list()

        # Read the CSV file for L2 firewall rules
        if l2config == "":
            l2config="l2firewall.config"
            
        if l3config == "":
            l3config="l3firewall.config" 
        with open(l2config, 'r') as rules: # Changed 'rb' to 'r' for text mode compatibility
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
        with open(l3config, 'r') as csvfile: # Changed 'rb' to 'r' for text mode compatibility
            log.debug("Reading L3 firewall config file !")
            self.rules = csv.DictReader(csvfile)
            self.l3_rules_list = [] # Store L3 rules as a list for later use
            for row in self.rules:
                self.l3_rules_list.append(row)
                log.debug(f"Saving individual rule parameters in rule dict ! {row}") # f-string for better logging

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
        msg.priority = 1 # Lower priority to allow specific rules to take precedence
        event.connection.send(msg)

    # --- MODIFIED: installFlow function ---
    # Removed `action=of.OFPAT_DROP` from signature.
    # Added `drop_packet` boolean flag to control action.
    def installFlow(self, event, offset, srcmac, dstmac, srcip, dstip, sport, dport, nwproto, drop_packet=False):
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        
        if srcip:
            match.nw_src = IPAddr(srcip)
        if dstip:
            match.nw_dst = IPAddr(dstip)    
        
        if nwproto is not None:
            match.nw_proto = int(nwproto)
        
        if srcmac:
            match.dl_src = srcmac
        if dstmac:
            match.dl_dst = dstmac
        
        if sport:
            match.tp_src = int(sport)
        if dport:
            match.tp_dst = int(dport)
            
        match.dl_type = pkt.ethernet.IP_TYPE
        msg.match = match
        msg.hard_timeout = 0
        msg.idle_timeout = 200
        msg.priority = priority + offset # This priority calculation needs to be careful with other rules        
        
        # --- Action based on drop_packet flag ---
        if drop_packet:
            # For OpenFlow 1.0, omitting actions or using OFPP_NONE drops the packet
            # msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE)) # Explicit drop
            log.debug(f"Installing DROP flow for match: {match}")
        else:
            # Default action for non-drop rules (e.g., allow to normal forwarding)
            # You might need more specific forwarding actions here depending on your L3 rules
            # For now, it will rely on other rules (like allowOther or l3_learning)
            # or you can add a default output action if the rule is meant to forward.
            # E.g., msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD)) or to specific port
            log.debug(f"Installing FORWARD flow for match: {match}")
            # If this function is used to install forwarding rules, you need to add an action.
            # Since your L3Firewall.py's `replyToIP` calls this after reading block rules,
            # it might intend to just create a match to drop without explicit actions.
            # If `l3firewall.config` defines BLOCKING rules, then simply omitting `msg.actions.append` is correct.
            # If it's a mix, this `installFlow` needs to be more flexible.
            # For now, we assume `installFlow` with default `drop_packet=False` implies letting other rules handle it
            # or it's implicitly a drop if no action is explicitly added for a match.
            pass # No action added, means packet will be dropped if no lower priority rule forwards it.
        # --- End Action based on drop_packet flag ---

        event.connection.send(msg)

    def replyToIP(self, packet, match, event, fwconfig):
        # The fwconfig here refers to self.l3_rules_list
        
        for row in fwconfig: # Iterate over the loaded L3 rules
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
            prio1 = int(prio) if prio is not None and prio != 'any' else priority

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
                continue # Skip this rule if protocol is not valid or "any"

            # This part attempts to install a flow rule for EACH L3 rule.
            # Assuming L3 rules from config are meant to block, we call installFlow with drop_packet=True
            self.installFlow(event, prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1, drop_packet=True)
        
        # After attempting to install L3 specific rules, allow other traffic to flow normally.
        # This will be overridden by higher priority rules (like our port security or L2 rules).
        self.allowOther(event)


    def _handle_ConnectionUp (self, event):
        self.connection = event.connection

        # Install L2 blocking rules from l2firewall.config
        for (source, destination) in self.disbaled_MAC_pair:
            print(f"Installing L2 block rule: {source} -> {destination}")
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

            log.debug(f"PacketIn from {src_mac} (IP: {src_ip}) on port {event.port}")

            # 1. Check if this MAC is already permanently blocked due to a previous spoofing attempt
            if src_mac in blocked_macs:
                log.info(f"Blocked MAC {src_mac} (IP: {src_ip}) attempted to send traffic. Dropping packet.")
                return # Drop the packet by not processing it further

            # 2. Implement Port Security Pseudo-code:
            # For any newly received flow, F originated from the source MAC address F.SrcMAC;
            # if F.SrcIP is new;
            #     update PT with the mapping F.SrcMAC <--> F.SrcIP;
            # else
            #     block F.SrcMAC % Block a MAC address that had spoofed multiple IP addresses
            # end

            if src_mac not in port_security_table:
                # First time seeing this MAC, record its associated IP
                log.info(f"Port Security: New MAC-IP mapping established: {src_mac} <--> {src_ip}")
                port_security_table[src_mac] = src_ip
            else:
                # MAC is known, check if the IP is consistent
                expected_ip = port_security_table[src_mac]
                if src_ip != expected_ip:
                    # Port security violation detected!
                    log.warning(f"Port Security VIOLATION: MAC {src_mac} (expected IP: {expected_ip}) is spoofing IP {src_ip}. Blocking this MAC permanently.")
                    
                    # Add MAC to `blocked_macs` to prevent repeated detection and rule installations
                    blocked_macs.add(src_mac)

                    # Install a flow rule to block all future traffic from this source MAC
                    msg = of.ofp_flow_mod()
                    msg.match.dl_src = src_mac
                    # Use a very high priority to ensure it overrides everything else
                    msg.priority = of.OFP_DEFAULT_PRIORITY + 20000 
                    msg.idle_timeout = 0 # Don't expire
                    msg.hard_timeout = 0 # Don't expire
                    # No actions means drop the packet implicitly for OpenFlow 1.0
                    # Or explicitly: msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
                    event.connection.send(msg)

                    log.info(f"Port Security: Installed flow rule to block ALL traffic from malicious MAC: {src_mac}.")
                    return # Drop the current spoofed packet by not processing it further

            # If the packet passed port security, proceed with other IP-related firewall rules/forwarding
            # Your existing `replyToIP` function will then be called to apply L3 rules.
            self.replyToIP(packet, match, event, self.l3_rules_list)

        # If it's not ARP or IP, it will be implicitly handled by `l3_learning` or `allowOther` if it's installed.

def launch (l2config="l2firewall.config",l3config="l3firewall.config"):
    core.registerNew(Firewall, l2config, l3config)
