from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
from collections import namedtuple
import os
import csv
import argparse
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

log = core.getLogger()
priority = 50000

l2config = "l2firewall.config"
l3config = "l3firewall.config"


class Firewall (EventMixin):

    # Dictionary to store MAC-to-IP mappings for port security
    # Format: {mac_address: ip_address}
    # A MAC should only be associated with one IP at a time.
    port_security_table = {}

    def __init__ (self,l2config,l3config):
        self.listenTo(core.openflow)
        self.disbaled_MAC_pair = [] # Store a tuple of MAC pair which will be installed into the flow table of each switch.
        self.fwconfig = list()

        '''
        Read the CSV file for L2 rules
        '''
        if l2config == "":
            l2config="l2firewall.config"
            
        if l3config == "":
            l3config="l3firewall.config" 
        
        # Ensure l2firewall.config exists, create if not
        if not os.path.exists(l2config):
            with open(l2config, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["id", "mac_0", "mac_1"]) # Write header
            log.info(f"Created empty {l2config} file.")

        with open(l2config, 'r') as rules: # Changed 'rb' to 'r' for text mode
            csvreader = csv.DictReader(rules) # Map into a dictionary
            for line in csvreader:
                # Read MAC address. Convert string to Ethernet address using the EthAddr() function.
                mac_0 = EthAddr(line['mac_0']) if line['mac_0'] != 'any' else None
                mac_1 = EthAddr(line['mac_1']) if line['mac_1'] != 'any' else None
                # Append to the array storing all MAC pair.
                self.disbaled_MAC_pair.append((mac_0,mac_1))

        # Ensure l3firewall.config exists, create if not
        if not os.path.exists(l3config):
            with open(l3config, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["priority", "src_mac", "dst_mac", "src_ip", "dst_ip", "src_port", "dst_port", "nw_proto"]) # Write header
            log.info(f"Created empty {l3config} file.")

        with open(l3config) as csvfile:
            log.debug("Reading L3 firewall rules file !")
            self.rules = list(csv.DictReader(csvfile)) # Read all rules into a list
            for row in self.rules:
                log.debug("Saving individual rule parameters in rule dict !")
                s_ip = row.get('src_ip', 'any')
                d_ip = row.get('dst_ip', 'any')
                s_port = row.get('src_port', 'any')
                d_port = row.get('dst_port', 'any')
                print "src_ip, dst_ip, src_port, dst_port", s_ip,d_ip,s_port,d_port

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

    def installFlow(self, event, offset, srcmac, dstmac, srcip, dstip, sport, dport, nwproto, action_port=None, drop=False):
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
        
        if sport is not None:
            match.tp_src = sport
        if dport is not None:
            match.tp_dst = dport
        
        match.dl_type = pkt.ethernet.IP_TYPE # Ensure it's an IP packet

        msg.match = match
        msg.hard_timeout = 0
        msg.idle_timeout = 200
        msg.priority = priority + offset # Use the provided offset for priority

        if drop:
            # Explicitly drop the packet (no actions means drop in OpenFlow 1.0)
            # Or use OFPP_NONE if explicit action is preferred
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE)) 
            log.debug(f"Installing DROP flow: {match}")
        elif action_port is not None:
            msg.actions.append(of.ofp_action_output(port = action_port))
            log.debug(f"Installing FORWARD flow to port {action_port}: {match}")
        else:
            # Fallback for forwarding if no specific action_port is given
            # This should ideally not be hit if l3_learning is also active.
            # For this context, if no explicit action, it means drop (firewall)
            log.debug(f"Installing flow with no explicit action (potential drop): {match}")


        event.connection.send(msg)

    def replyToIP(self, packet, match, event):
        # --- PORT SECURITY LOGIC ADDED HERE ---
        src_mac = str(match.dl_src)
        src_ip = str(match.nw_src)
        
        # Check if this MAC address has been seen with a different IP
        if src_mac in self.port_security_table:
            if self.port_security_table[src_mac] != src_ip:
                log.info(f"!!! PORT SECURITY VIOLATION !!! MAC {src_mac} (originally {self.port_security_table[src_mac]}) now seen with IP {src_ip}. Blocking this MAC.")
                # Install a high-priority rule to drop all traffic from this spoofing MAC
                msg = of.ofp_flow_mod()
                msg.priority = 65535 # Very high priority
                msg.match.dl_src = match.dl_src # Match the spoofing MAC
                msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE)) # Explicitly drop
                event.connection.send(msg)

                # Also add this rule to l2firewall.config for persistence if POX restarts
                # This part is for demonstration, in production you might have a more robust way
                # to manage dynamic blacklist.
                with open(l2config, 'a', newline='') as f:
                    writer = csv.writer(f)
                    # Generate a simple ID (e.g., current timestamp)
                    rule_id = int(time.time()) 
                    writer.writerow([rule_id, src_mac, "any"])
                log.info(f"Added blocking rule for {src_mac} to {l2config}")

                return # Block the packet, do not process further
        else:
            # First time seeing this MAC, bind it to its current IP
            self.port_security_table[src_mac] = src_ip
            log.info(f"Port security: MAC {src_mac} bound to IP {src_ip}")

        # --- END PORT SECURITY LOGIC ---

        # Process L3 firewall rules (from l3firewall.config)
        # Re-read rules to ensure latest config is used (though inefficient, matches original structure)
        with open(l3config) as csvfile:
            current_l3_rules = list(csv.DictReader(csvfile))

        packet_blocked_by_l3_fw = False
        for row in current_l3_rules:
            try:
                prio = int(row.get('priority', priority))
                rule_srcmac = EthAddr(row['src_mac']) if row.get('src_mac') and row['src_mac'] != 'any' else None
                rule_dstmac = EthAddr(row['dst_mac']) if row.get('dst_mac') and row['dst_mac'] != 'any' else None
                rule_src_ip = IPAddr(row['src_ip']) if row.get('src_ip') and row['src_ip'] != 'any' else None
                rule_dst_ip = IPAddr(row['dst_ip']) if row.get('dst_ip') and row['dst_ip'] != 'any' else None
                rule_src_port = int(row['src_port']) if row.get('src_port') and row['src_port'] != 'any' else None
                rule_dst_port = int(row['dst_port']) if row.get('dst_port') and row['dst_port'] != 'any' else None
                rule_nw_proto_str = row.get('nw_proto', '').lower()

                nw_proto_val = None
                if rule_nw_proto_str == "tcp":
                    nw_proto_val = pkt.ipv4.TCP_PROTOCOL
                elif rule_nw_proto_str == "icmp":
                    nw_proto_val = pkt.ipv4.ICMP_PROTOCOL
                elif rule_nw_proto_str == "udp":
                    nw_proto_val = pkt.ipv4.UDP_PROTOCOL
                
                # Check if current packet matches this L3 firewall rule
                match_criteria = True
                if rule_srcmac and match.dl_src != rule_srcmac: match_criteria = False
                if rule_dstmac and match.dl_dst != rule_dstmac: match_criteria = False
                if rule_src_ip and match.nw_src != rule_src_ip: match_criteria = False
                if rule_dst_ip and match.nw_dst != rule_dst_ip: match_criteria = False
                if nw_proto_val and match.nw_proto != nw_proto_val: match_criteria = False
                if rule_src_port and match.tp_src != rule_src_port: match_criteria = False
                if rule_dst_port and match.tp_dst != rule_dst_port: match_criteria = False

                if match_criteria:
                    log.info(f"Packet matched L3 firewall rule. Blocking: {match}")
                    # Install a drop flow for this specific L3 rule
                    self.installFlow(event, prio, rule_srcmac, rule_dstmac, rule_src_ip, rule_dst_ip, rule_src_port, rule_dst_port, nw_proto_val, drop=True)
                    packet_blocked_by_l3_fw = True
                    break # Blocked by an L3 rule, no need to check further L3 rules

            except Exception as e:
                log.error(f"Error parsing L3 firewall rule row {row}: {e}")
                continue

        if packet_blocked_by_l3_fw:
            return # Packet was blocked by L3 firewall, do not forward

        # If not blocked by port security or L3 firewall, let l3_learning handle it
        # This relies on the l3_learning module to install forwarding rules.
        # POX's l3_learning works by sending PacketOuts and installing flows.
        # We don't need to explicitly call allowOther here if l3_learning is active.
        # However, to ensure *some* forwarding happens if l3_learning is slow or absent,
        # we can add a PacketOut for this specific packet.
        
        # A simple PacketOut to ensure the packet is forwarded if no flow exists yet
        # and l3_learning hasn't installed one.
        # This is a fallback and not a flow rule installation.
        # The l3_learning component itself will install the actual flow rules.
        # No explicit action needed here, as l3_learning will handle the forwarding.


    def _handle_ConnectionUp (self, event):
        ''' Add your logic here ... '''
        self.connection = event.connection

        # Install L2 blocking rules from disbaled_MAC_pair
        for (source, destination) in self.disbaled_MAC_pair:
            print source,destination
            message = of.ofp_flow_mod() # OpenFlow massage. Instructs a switch to install a flow
            match = of.ofp_match() # Create a match
            match.dl_src = source # Source address
            match.dl_dst = destination # Destination address
            message.priority = 65535 # Set priority (between 0 and 65535)
            message.match = match            
            message.actions.append(of.ofp_action_output(port = of.OFPP_NONE)) # Explicitly drop
            event.connection.send(message) # Send instruction to the switch

        # ADDED: A lower priority NORMAL flow. This ensures that if no other rules match,
        # traffic still gets forwarded normally by the switch's pipeline,
        # and l3_learning can still operate for new flows.
        msg = of.ofp_flow_mod()
        msg.priority = 1 # A low priority, higher than default 0 but lower than blocking rules
        msg.actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
        event.connection.send(msg)
        
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

    def _handle_PacketIn(self, event):

        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        match = of.ofp_match.from_packet(packet)

        if match.dl_type == packet.ARP_TYPE:
            # Handle ARP requests
            if match.nw_proto == arp.REQUEST:
                self.replyToARP(packet, match, event)
            return # ARP handled, no further processing for this packet

        if match.dl_type == packet.IP_TYPE:
            ip_packet = packet.payload
            # Ensure IP packet is parsed
            if not ip_packet.parsed:
                log.warning("Ignoring incomplete IP packet")
                return

            log.debug("IP packet protocol = %s", ip_packet.protocol)
            
            # Call replyToIP for IP packets to apply port security and L3 firewall rules
            self.replyToIP(packet, match, event)
            
            # If the packet was not blocked by replyToIP, it will fall through
            # to l3_learning (which is launched alongside L3Firewall)
            # l3_learning will then install the forwarding rules.
            # We don't need to explicitly send a PacketOut here as l3_learning handles it.


def launch (l2config="l2firewall.config",l3config="l3firewall.config"):
    '''
    Starting the Firewall module
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('--l2config', action='store', dest='l2config',
                    help='Layer 2 config file', default='l2firewall.config')
    parser.add_argument('--l3config', action='store', dest='l3config',
                    help='Layer 3 config file', default='l3firewall.config')
    core.registerNew(Firewall,l2config,l3config)
