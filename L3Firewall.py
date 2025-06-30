from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
from pox.lib.revent import EventMixin # Added EventMixin
import os
import csv
import argparse # Added argparse for launch function

log = core.getLogger()

class Firewall (EventMixin): # Inherit from EventMixin
  def __init__ (self, l2config, l3config):
    self.l2config_file = l2config
    self.l3config_file = l3config # This will be empty or contain dummy rules for this approach

    # This will store (source_mac_to_block, dest_mac_any_or_specific) tuples
    self.l2_blocked_mac_pairs = []

    # Removed in-controller port security data structures
    # self.mac_ip_map = {}
    # self.blocked_macs = set()

    core.openflow.addListenerByName("PacketIn", self._handle_PacketIn)
    core.openflow.addListenerByName("ConnectionUp", self._handle_ConnectionUp)

    log.info("Initializing L3Firewall module...")
    self.load_l2_firewall_rules()
    self.load_l3_firewall_rules() # This will load an empty set of rules if file is empty

  def load_l2_firewall_rules(self):
    self.l2_blocked_mac_pairs = [] # Clear existing rules
    if not os.path.exists(self.l2config_file):
        log.warning("L2 firewall config file %s not found. No L2 rules loaded." % self.l2config_file)
        return

    try:
        with open(self.l2config_file, 'r', newline='') as f:
            reader = csv.reader(f)
            header = next(reader, None) # Skip header line, e.g., "id,mac_0,mac_1"
            if header: # Log header if it exists
                log.info("L2 firewall config header: %s" % (", ".join(header)))

            log.info("Loading L2 firewall rules from %s" % self.l2config_file)
            for row in reader:
                if len(row) >= 2:
                    # Assuming format: id,mac_0,mac_1
                    # mac_0 is the source MAC to block
                    source_mac_str = row[1].strip()
                    dest_mac_str = row[2].strip() if len(row) > 2 else "any"

                    if source_mac_str != 'any':
                        try:
                            source_mac = EthAddr(source_mac_str)
                            dest_mac = EthAddr(dest_mac_str) if dest_mac_str.lower() != 'any' else None
                            self.l2_blocked_mac_pairs.append((source_mac, dest_mac))
                            log.debug("Loaded L2 block rule: src_mac=%s, dst_mac=%s" % (source_mac, dest_mac_str))
                        except Exception as e:
                            log.error("Error parsing L2 rule line '%s': %s" % (",".join(row), e))
    except Exception as e:
        log.error("Error loading L2 firewall config from %s: %s" % (self.l2config_file, e))
        self.l2_blocked_mac_pairs = [] # Ensure it's empty on failure
    log.info("Loaded %s L2 firewall rules." % len(self.l2_blocked_mac_pairs))

  def load_l3_firewall_rules(self):
      # This function would load L3 rules from self.l3config_file
      # Since l3firewall.config is empty for this approach, this function
      # will likely do nothing or simply log that no rules were found.
      # Keep it for completeness if you decide to add L3 rules later.
      log.info("Attempting to load L3 firewall rules from %s (currently empty for this approach)." % self.l3config_file)
      self.rules = [] # Ensure self.rules is defined, even if empty
      if not os.path.exists(self.l3config_file):
          log.warning("L3 firewall config file %s not found. No L3 rules loaded." % self.l3config_file)
          return
      # Add your L3 parsing logic here if you ever add rules to l3firewall.config
      # For now, it will remain empty, thus no L3 rules will block traffic.

  def install_flow (self, match, action=of.OFPAT_DROP, priority=None):
    """
    Installs a flow rule to the switch.
    'action' can be of.OFPAT_DROP for blocking, or of.OFPAT_OUTPUT for forwarding.
    """
    msg = of.ofp_flow_mod()
    msg.match = match
    if priority:
        msg.priority = priority
    else:
        msg.priority = 1000 # Default priority

    if action == of.OFPAT_DROP:
        log.debug("Installing drop flow for match: %s" % match)
        # No actions means drop
    elif action == of.OFPAT_OUTPUT:
        log.debug("Installing output flow with actions for match: %s" % match)
        # This function typically requires the output port.
        # For simplicity, if used for allowOther, it might just use OFPP_NORMAL or OFPP_FLOOD
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL)) # Example for normal forwarding
    else:
        log.warning("Unknown action specified for install_flow.")
        return

    # Assuming 'self.connection' is set up for the current switch
    # In PacketIn, you would use event.connection.send(msg) directly.
    # This install_flow is more generic, so ensure 'conn' is passed or available.
    # For initial setup in ConnectionUp, self.connection is correct.
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
    #log.debug("No firewall rule explicitly blocked the packet. Allowing/learning traffic from %s" % packet.src)

    # Standard learning switch behavior:
    # If the destination is known, forward directly. Otherwise, flood.
    # For a simple L3Firewall, OFPP_NORMAL is often used for unhandled traffic
    # as it defers to the switch's normal (e.g., L2 learning) behavior.

    # If you want explicit learning, you'd store (MAC, port) mappings.
    # For now, let's install a short-lived flow using OFPP_NORMAL (or FLOOD)
    # This assumes the switch itself handles basic L2 learning.
    
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.idle_timeout = 10 # Short timeout for dynamic learning
    msg.hard_timeout = 30
    
    # If you have specific host-to-port mappings, you can use them here.
    # For a simple learning switch, often a flood rule or OFPP_NORMAL is sufficient
    # to let the switch learn where the destination is.
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) # Or OFPP_NORMAL
    
    event.connection.send(msg)

  def _handle_PacketIn (self, event):
    packet = event.parsed
    if not packet.parsed:
        log.warning("Ignoring unparsed packet")
        return

    # --- L2 Firewall check (from l2firewall.config, updated by monitor.py) ---
    # Iterate through the pre-loaded L2 blocking rules
    for source_mac_to_block, dest_mac_if_specific in self.l2_blocked_mac_pairs:
        if packet.src == source_mac_to_block:
            # If a specific destination MAC is defined for this rule, check it
            if dest_mac_if_specific is None or (packet.dst == dest_mac_if_specific):
                log.info("Packet from MAC %s blocked by L2 firewall rule (matched: %s->%s)." % (packet.src, source_mac_to_block, dest_mac_if_specific))
                # Install a permanent drop flow for this MAC on its ingress port
                msg = of.ofp_flow_mod()
                msg.match.dl_src = packet.src
                # Optionally, match on ingress port for more specific blocking
                # msg.match.in_port = event.port
                if dest_mac_if_specific:
                    msg.match.dl_dst = dest_mac_if_specific
                msg.priority = 65535 # Very high priority to ensure it's dropped
                # No actions means drop
                event.connection.send(msg)
                return # Packet dropped, stop further processing

    # --- ARP handling ---
    if packet.type == pkt.ethernet.ARP_TYPE:
        # Your existing replyToARP logic (ensure it uses .format() or %)
        # You need to ensure replyToARP is defined and works correctly
        log.debug("ARP packet received: %s" % packet.next)
        self.replyToARP(packet, of.ofp_match.from_packet(packet), event)
        return

    # --- IP Packet handling (L3 rules if any, otherwise allow) ---
    ip_packet = packet.find('ipv4')
    if not ip_packet:
        # Not an IP packet (e.g., LLDP, spanning tree, etc.), or not handled
        self.allowOther(event)
        return

    # *** Removed in-controller port security logic from here ***
    # The logic that checked self.mac_ip_map and self.blocked_macs
    # and dynamically installed drop flows for spoofing is gone.
    # That is now handled by monitor.py updating l2firewall.config.

    # --- L3 Firewall check (from l3firewall.config, which is empty) ---
    # This loop will essentially do nothing if self.rules is empty.
    # If you later add L3 rules to l3firewall.config, this is where they would be applied.
    blocked_by_l3_rule = False
    # for rule in self.rules:
    #    # ... your L3 rule matching logic ...
    #    if rule_matches_packet:
    #        log.info("Packet matched L3 Firewall rule. Installing blocking flow.")
    #        match_l3 = of.ofp_match.from_packet(packet) # Create a new match for L3
    #        # You might want to match on specific IP/protocol fields for L3 rules
    #        # Example: match_l3.nw_src = IPAddr(rule.src_ip)
    #        self.install_flow(match_l3, action=of.OFPAT_DROP, priority=rule.priority)
    #        blocked_by_l3_rule = True
    #        break

    if not blocked_by_l3_rule:
        self.allowOther(event) # If not blocked by L2 or L3, allow

  def _handle_ConnectionUp (self, event):
    """
    Called when a switch connects to the controller.
    Installs pre-defined L2 blocking rules.
    """
    self.connection = event.connection # Store the connection for this switch
    log.info("Switch %s connected. Installing initial L2 firewall rules." % dpid_to_str(event.dpid))
    for source_mac, dest_mac in self.l2_blocked_mac_pairs:
        msg = of.ofp_flow_mod()
        msg.match.dl_src = source_mac
        if dest_mac:
            msg.match.dl_dst = dest_mac
        msg.priority = 65535 # High priority
        # No actions means drop
        event.connection.send(msg)
        log.info("Installed initial L2 block flow for MAC %s (on switch %s)" % (source_mac, dpid_to_str(event.dpid)))

  # --- Your existing helper functions (replyToARP, replyToIP etc.) ---
  # Make sure these are also converted from f-strings and are part of the class.

  def replyToARP(self, packet, match, event):
    """Handles ARP requests and replies for known hosts."""
    r = pkt.arp()
    r.hwsrc = match.dl_dst # This assumes the controller knows the correct MACs of hosts
    r.protosrc = match.nw_dst
    r.hwdst = match.dl_src
    r.protodst = match.nw_src
    r.opcode = pkt.arp.REPLY
    e = pkt.ethernet(type=packet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
    e.set_payload(r)
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port=event.port))
    event.connection.send(msg)
    log.debug("Sent ARP reply from %s to %s" % (r.protosrc, r.protodst))

  # No need for replyToIP if you are not doing L3 learning in the controller.
  # If you do, ensure it follows the same pattern.
  # def replyToIP(self, packet, match, event, fwconfig):
  #     pass


def launch (l2config="l2firewall.config", l3config="l3firewall.config"):
  """
  Launches the Firewall module.
  """
  # Check if config files exist, if not, create them with headers
  if not os.path.exists(l2config):
      with open(l2config, 'w', newline='') as f:
          writer = csv.writer(f)
          writer.writerow(["id", "mac_0", "mac_1"])
      log.info("Created empty L2 firewall config file: %s" % l2config)
  
  if not os.path.exists(l3config):
      # L3 is expected to be empty for this approach, so just create with header
      with open(l3config, 'w', newline='') as f:
          writer = csv.writer(f)
          writer.writerow(["id", "src_ip", "dst_ip", "nw_proto", "src_port", "dst_port", "priority"])
      log.info("Created empty L3 firewall config file: %s" % l3config)


  core.registerNew(Firewall, l2config, l3config)
