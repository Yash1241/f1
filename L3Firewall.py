from pox.core import core
# Explicitly import common OF constants and classes from libopenflow_01
# This ensures Python 2.7 compatibility for constants and class names.
from pox.openflow.libopenflow_01 import (
    OFPAT_DROP, OFPAT_OUTPUT, OFPP_FLOOD, OFPP_NORMAL,
    ofp_flow_mod, ofp_match, ofp_action_output, ofp_packet_out,
    OFPP_IN_PORT
)
import pox.openflow.libopenflow_01 as of # Keep this for other 'of.' references like of.ARP_REPLY, of.IP_TYPE
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
from pox.lib.revent import EventMixin
import os
import csv
import argparse

log = core.getLogger()

class Firewall (EventMixin):
  def __init__ (self, l2config, l3config):
    self.l2config_file = l2config
    self.l3config_file = l3config

    self.l2_blocked_mac_pairs = [] # Stores static L2 rules from l2firewall.config
    self.mac_ip_map = {} # Maps MAC to a single known IP (for port security detection)
    self.blocked_macs = set() # Stores MACs identified as spoofing (for blocking)

    core.openflow.addListenerByName("PacketIn", self._handle_PacketIn)
    core.openflow.addListenerByName("ConnectionUp", self._handle_ConnectionUp)

    log.info("Initializing L3Firewall module...")
    self.load_l2_firewall_rules()
    self.load_l3_firewall_rules() # This will be empty but keeps the structure

  def load_l2_firewall_rules(self):
    self.l2_blocked_mac_pairs = [] # Clear existing rules before loading
    if not os.path.exists(self.l2config_file):
        log.warning("L2 firewall config file %s not found. No L2 rules loaded." % self.l2config_file)
        return

    try:
        # Python 2.7 does not use newline='' for csv.reader
        with open(self.l2config_file, 'r') as f:
            reader = csv.reader(f)
            header = next(reader, None) # Skip header line
            if header:
                log.info("L2 firewall config header: %s" % (", ".join(header)))

            log.info("Loading L2 firewall rules from %s" % self.l2config_file)
            for row in reader:
                if len(row) >= 2: # Ensure enough columns for at least source MAC
                    source_mac_str = row[1].strip() # Assuming 'mac_0' is column 1
                    dest_mac_str = row[2].strip() if len(row) > 2 else "any" # Assuming 'mac_1' is column 2

                    if source_mac_str.lower() != 'any': # Check for 'any' MAC
                        try:
                            source_mac = EthAddr(source_mac_str)
                            # If destination is 'any', dest_mac will be None
                            dest_mac = EthAddr(dest_mac_str) if dest_mac_str.lower() != 'any' else None
                            self.l2_blocked_mac_pairs.append((source_mac, dest_mac))
                            log.debug("Loaded L2 block rule: src_mac=%s, dst_mac=%s" % (source_mac, dest_mac_str))
                        except Exception as e:
                            log.error("Error parsing L2 rule line '%s': %s" % (",".join(row), e))
    except Exception as e:
        log.error("Error loading L2 firewall config from %s: %s" % (self.l2config_file, e))
        self.l2_blocked_mac_pairs = [] # Ensure it's empty if an error occurs
    log.info("Loaded %s L2 firewall rules." % len(self.l2_blocked_mac_pairs))

  def load_l3_firewall_rules(self):
      # This function would load L3 rules from self.l3config_file.
      # For now, it's just a placeholder as Task 3 focuses on L2 and port security.
      log.info("Attempting to load L3 firewall rules from %s (currently empty)." % self.l3config_file)
      self.rules = [] # Ensure self.rules is defined, even if empty
      if not os.path.exists(self.l3config_file):
          log.warning("L3 firewall config file %s not found. No L3 rules loaded." % self.l3config_file)
          return
      # Add your L3 parsing logic here if you ever add rules to l3firewall.config

  def install_flow (self, match, action_type=OFPAT_DROP, priority=None):
    """
    Installs a flow rule to the switch.
    'action_type' can be OFPAT_DROP for blocking, or OFPAT_OUTPUT for forwarding.
    """
    msg = ofp_flow_mod()
    msg.match = match
    if priority:
        msg.priority = priority
    else:
        msg.priority = 1000 # Default priority for general flows

    if action_type == OFPAT_DROP:
        log.debug("Installing drop flow for match: %s" % match)
        # No actions appended means drop by default in OpenFlow 1.0
    elif action_type == OFPAT_OUTPUT:
        log.debug("Installing output flow with actions for match: %s" % match)
        msg.actions.append(ofp_action_output(port=OFPP_NORMAL)) # Forward out normal ports
    else:
        log.warning("Unknown action_type specified for install_flow.")
        return

    if hasattr(self, 'connection') and self.connection:
        self.connection.send(msg)
    else:
        log.error("No active connection to send flow modification.")

  def allowOther (self, event):
    """
    This is the default learning switch behavior for packets not explicitly blocked.
    It learns MAC addresses and floods/forwards.
    """
    packet = event.parsed
    
    msg = ofp_flow_mod()
    msg.match = ofp_match.from_packet(packet)
    msg.idle_timeout = 10 # Short timeout for dynamic learning
    msg.hard_timeout = 30 # Hard timeout to clear old entries
    
    # Send to normal OpenFlow port for learning/forwarding
    msg.actions.append(ofp_action_output(port = OFPP_NORMAL))
    
    event.connection.send(msg)

  def _handle_PacketIn (self, event):
    packet = event.parsed
    if not packet.parsed:
        log.warning("Ignoring unparsed packet")
        return

    # --- 1. Static L2 Firewall Rule Check (from l2firewall.config) ---
    for source_mac_to_block, dest_mac_if_specific in self.l2_blocked_mac_pairs:
        if packet.src == source_mac_to_block:
            # If dest_mac_if_specific is None, it means block any destination for source_mac_to_block
            if dest_mac_if_specific is None or (packet.dst == dest_mac_if_specific):
                log.info("Packet from MAC %s blocked by L2 firewall rule (matched: %s->%s)." % (packet.src, source_mac_to_block, dest_mac_if_specific))
                # Install a permanent drop flow for this specific L2 rule
                match = ofp_match(dl_src=packet.src)
                if dest_mac_if_specific:
                    match.dl_dst = dest_mac_if_specific
                self.install_flow(match, action_type=OFPAT_DROP, priority=65535) # Highest priority
                return # Packet dropped, stop further processing

    # --- 2. Port Security Logic (Dynamic Spoofing Detection) ---
    # First, check if the source MAC is already identified as a spoofer and blocked
    if packet.src in self.blocked_macs:
        log.debug("Packet from already blocked spoofing MAC %s dropped." % packet.src)
        # A high-priority drop flow for this MAC should already be installed by _handle_ConnectionUp or previous detection.
        return # Drop the packet, no further processing needed

    # Handle ARP packets for basic network discovery
    if packet.type == pkt.ethernet.ARP_TYPE:
        log.debug("ARP packet received from %s (IP: %s) for %s (IP: %s)" % (packet.src, packet.next.protosrc, packet.dst, packet.next.protodst))
        # ARP requests are generally allowed for learning and initial communication.
        # replyToARP will generate a reply for direct ARP requests.
        self.replyToARP(packet, ofp_match.from_packet(packet), event)
        # Important: Allow ARP to continue for learning, don't return here if you want learning to proceed from ARPs.
        # For strict port security, you might filter ARPs after learning.
        # For now, let's allow it to fall through to IP check if it is also an IP packet (e.g. ARP over IP)
        # or proceed to allowOther if it's only ARP.

    # Process IP packets for spoofing detection
    ip_packet = packet.find('ipv4')
    if ip_packet:
        if packet.src not in self.mac_ip_map:
            # First time seeing this MAC, map it to its current IP address
            self.mac_ip_map[packet.src] = ip_packet.srcip
            log.info("Port security: Learned MAC %s -> IP %s" % (packet.src, ip_packet.srcip))
        elif self.mac_ip_map[packet.src] != ip_packet.srcip:
            # Existing MAC is now using a different IP - potential spoofing!
            log.warning("!!! SPOOFING DETECTED !!! MAC %s (original IP: %s) is now using IP %s" % (packet.src, self.mac_ip_map[packet.src], ip_packet.srcip))
            self.blocked_macs.add(packet.src) # Add to the set of blocked spoofing MACs

            # Install a high-priority drop flow for all IP traffic from this spoofing MAC
            # This makes the blocking persistent on the switch.
            match = ofp_match(dl_src=packet.src, dl_type=of.IP_TYPE) # Match all IP traffic from this MAC
            self.install_flow(match, action_type=OFPAT_DROP, priority=65535)
            log.info("Blocking future IP traffic from spoofing MAC: %s" % packet.src)
            return # Drop this spoofed packet and stop processing

    # --- 3. L3 Firewall Check (Placeholder) ---
    blocked_by_l3_rule = False
    # (Your L3 rule matching logic would go here if you had L3 rules to check against packet.srcip, packet.dstip, ports, etc.)
    # Example (conceptual):
    # if ip_packet:
    #    for rule in self.rules:
    #        if (rule.src_ip is None or ip_packet.srcip == rule.src_ip) and \
    #           (rule.dst_ip is None or ip_packet.dstip == rule.dst_ip) and \
    #           etc.:
    #            blocked_by_l3_rule = True
    #            log.info("Packet blocked by L3 rule.")
    #            self.install_flow(ofp_match.from_packet(packet), OFPAT_DROP, rule.priority)
    #            return # Drop and stop

    if not blocked_by_l3_rule:
        self.allowOther(event) # If not blocked by L2 or spoofing, allow/learn

  def _handle_ConnectionUp (self, event):
    """
    Called when a switch connects to the controller.
    Installs pre-defined L2 blocking rules and re-applies dynamic spoofing block rules.
    """
    self.connection = event.connection # Store the connection object for this switch
    log.info("Switch %s connected. Installing initial firewall rules." % dpid_to_str(event.dpid))

    # Install initial static L2 block rules loaded from config
    for source_mac, dest_mac in self.l2_blocked_mac_pairs:
        match = ofp_match(dl_src=source_mac)
        if dest_mac: # If a specific destination MAC is specified for the rule
            match.dl_dst = dest_mac
        self.install_flow(match, action_type=OFPAT_DROP, priority=65535)
        log.info("Installed initial static L2 block flow for MAC %s->%s (on switch %s)" % (source_mac, dest_mac, dpid_to_str(event.dpid)))

    # Re-install dynamic spoofing block rules for any MACs previously identified as spoofers
    # This ensures persistent blocking even if the switch reconnects or controller restarts
    for mac in self.blocked_macs:
        match = ofp_match(dl_src=mac, dl_type=of.IP_TYPE) # Block all IP traffic from this spoofing MAC
        self.install_flow(match, action_type=OFPAT_DROP, priority=65535)
        log.info("Re-installed block flow for spoofing MAC %s on switch %s" % (mac, dpid_to_str(event.dpid)))

  def replyToARP(self, packet, match, event):
    """Handles ARP requests and replies."""
    r = pkt.arp()
    r.hwsrc = match.dl_dst # This is the switch's MAC for the requested IP
    r.protosrc = match.nw_dst # This is the IP for which the switch is replying
    r.hwdst = match.dl_src # The MAC of the original sender
    r.protodst = match.nw_src # The IP of the original sender
    r.opcode = pkt.arp.REPLY # The opcode for an ARP reply

    e = pkt.ethernet(type=packet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
    e.set_payload(r)

    msg = ofp_packet_out()
    msg.data = e.pack()
    # Send the ARP reply back out the port it came in on (event.port)
    msg.actions.append(ofp_action_output(port=event.port))
    event.connection.send(msg)
    log.debug("Sent ARP reply from %s to %s for %s" % (r.protosrc, r.protodst, r.hwsrc))


def launch (l2config="l2firewall.config", l3config="l3firewall.config"):
  """
  Launches the Firewall module.
  """
  # Ensure config files exist with headers if they don't, to prevent IOError
  # Python 2.7 does not need newline='' for file open
  if not os.path.exists(l2config):
      with open(l2config, 'w') as f:
          writer = csv.writer(f)
          writer.writerow(["id", "mac_0", "mac_1"])
      log.info("Created empty L2 firewall config file: %s" % l2config)
  
  if not os.path.exists(l3config):
      with open(l3config, 'w') as f:
          writer = csv.writer(f)
          writer.writerow(["id", "src_ip", "dst_ip", "nw_proto", "src_port", "dst_port", "priority"])
      log.info("Created empty L3 firewall config file: %s" % l3config)

  core.registerNew(Firewall, l2config, l3config)
