from pox.core import core
# ONLY import the module, then reference everything via 'of.'
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
from pox.lib.revent import EventMixin
import os
import csv

log = core.getLogger()

class Firewall (EventMixin):
  def __init__ (self, l2config, l3config):
    self.l2config_file = l2config
    self.l3config_file = l3config

    self.l2_blocked_mac_pairs = [] # Stores static L2 rules
    self.mac_ip_map = {} # Stores {MAC_ADDRESS: IP_ADDRESS} for port security
    self.blocked_macs = set() # Stores MACs identified as spoofing

    core.openflow.addListenerByName("PacketIn", self._handle_PacketIn)
    core.openflow.addListenerByName("ConnectionUp", self._handle_ConnectionUp)

    log.info("Initializing L3Firewall module...")
    self.load_l2_firewall_rules()
    self.load_l3_firewall_rules() # Placeholder for L3 rules

  def load_l2_firewall_rules(self):
    self.l2_blocked_mac_pairs = []
    if not os.path.exists(self.l2config_file):
        log.warning("L2 firewall config file %s not found. No L2 rules loaded." % self.l2config_file)
        return

    try:
        with open(self.l2config_file, 'r') as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header:
                log.info("L2 firewall config header: %s" % (", ".join(header)))

            log.info("Loading L2 firewall rules from %s" % self.l2config_file)
            for row in reader:
                if len(row) >= 2:
                    source_mac_str = row[1].strip()
                    dest_mac_str = row[2].strip() if len(row) > 2 else "any"

                    if source_mac_str.lower() != 'any':
                        try:
                            source_mac = EthAddr(source_mac_str)
                            dest_mac = EthAddr(dest_mac_str) if dest_mac_str.lower() != 'any' else None
                            self.l2_blocked_mac_pairs.append((source_mac, dest_mac))
                            log.debug("Loaded L2 block rule: src_mac=%s, dst_mac=%s" % (source_mac, dest_mac_str))
                        except Exception as e:
                            log.error("Error parsing L2 rule line '%s': %s" % (",".join(row), e))
    except Exception as e:
        log.error("Error loading L2 firewall config from %s: %s" % (self.l2config_file, e))
        self.l2_blocked_mac_pairs = []
    log.info("Loaded %s L2 firewall rules." % len(self.l2_blocked_mac_pairs))

  def load_l3_firewall_rules(self):
      log.info("Attempting to load L3 firewall rules from %s (currently empty)." % self.l3config_file)
      self.rules = []
      if not os.path.exists(self.l3config_file):
          log.warning("L3 firewall config file %s not found. No L3 rules loaded." % self.l3config_file)
          return

  def install_flow (self, match, action_type=None, priority=None, idle_timeout=0, hard_timeout=0):
    """
    Installs a flow rule to the switch.
    'action_type' can be of.OFPAT_DROP for blocking, or of.OFPAT_OUTPUT for forwarding.
    """
    msg = of.ofp_flow_mod()
    msg.match = match
    if priority:
        msg.priority = priority
    else:
        msg.priority = 1000 # Default priority for general flows

    msg.idle_timeout = idle_timeout
    msg.hard_timeout = hard_timeout

    if action_type == of.OFPAT_DROP:
        log.debug("Installing drop flow for match: %s" % (match,))
        # No actions appended means drop by default in OpenFlow 1.0
    elif action_type == of.OFPAT_OUTPUT:
        log.debug("Installing output flow with actions for match: %s" % (match,))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL)) # Forward out normal ports
    else: # Default to OFPP_NORMAL if action_type is None or unrecognized
        log.debug("Installing default (of.OFPP_NORMAL) output flow for match: %s" % (match,))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))

    if hasattr(self, 'connection') and self.connection:
        self.connection.send(msg)
    else:
        log.error("No active connection to send flow modification.")

  def _handle_PacketIn (self, event):
    packet = event.parsed
    if not packet.parsed:
        log.warning("Ignoring unparsed packet")
        return

    # --- 1. Static L2 Firewall Rule Check (from l2firewall.config) ---
    for source_mac_to_block, dest_mac_if_specific in self.l2_blocked_mac_pairs:
        if packet.src == source_mac_to_block:
            if dest_mac_if_specific is None or (packet.dst == dest_mac_if_specific):
                log.info("Packet from MAC %s blocked by L2 firewall rule (matched: %s->%s)." % (packet.src, source_mac_to_block, dest_mac_if_specific))
                match = of.ofp_match(dl_src=packet.src)
                if dest_mac_if_specific:
                    match.dl_dst = dest_mac_if_specific
                self.install_flow(match, action_type=of.OFPAT_DROP, priority=65535, idle_timeout=0, hard_timeout=0)
                return

    # --- 2. Port Security Logic (Dynamic Spoofing Detection) ---
    ip_packet = packet.find('ipv4')
    if ip_packet:
        # First, check if the source MAC is already identified as a spoofer and blocked
        if packet.src in self.blocked_macs:
            log.debug("Packet from already blocked spoofing MAC %s dropped." % packet.src)
            return

        if packet.src not in self.mac_ip_map:
            self.mac_ip_map[packet.src] = ip_packet.srcip
            log.info("Port security: Learned MAC %s -> IP %s" % (packet.src, ip_packet.srcip))
        elif self.mac_ip_map[packet.src] != ip_packet.srcip:
            log.warning("!!! SPOOFING DETECTED !!! MAC %s (original IP: %s) is now using IP %s" % (packet.src, self.mac_ip_map[packet.src], ip_packet.srcip))
            self.blocked_macs.add(packet.src)

            match = of.ofp_match(dl_src=packet.src, dl_type=pkt.ethernet.IP_TYPE)
            self.install_flow(match, action_type=of.OFPAT_DROP, priority=65535, idle_timeout=0, hard_timeout=0)
            log.info("Blocking future IP traffic from spoofing MAC: %s" % packet.src)
            return

    # --- 3. L3 Firewall Check (Placeholder for custom L3 rules, not spoofing) ---
    # At this point, the packet is not blocked by L2 rules or port security.
    # If you had complex L3 rules based on IPs/ports, they would go here.
    # For now, it will simply fall through to the learning switch behavior.

    # --- 4. Default Learning Switch Behavior (if not blocked by above rules) ---
    # This handles ARP and legitimate IP traffic
    if packet.type == pkt.ethernet.ARP_TYPE:
        # For ARP, just let it pass through the learning switch logic.
        # The switch will flood it, and learning will happen.
        # No explicit ARP reply is needed from the controller unless it's acting as a proxy.
        pass # Allow ARP to fall through to the general learning/forwarding rule below

    # For any other legitimate traffic (including IP packets that passed spoofing checks)
    # The learning switch logic. Install a flow for the specific match.
    match = of.ofp_match.from_packet(packet)
    self.install_flow(match, action_type=of.OFPAT_OUTPUT, priority=1000, idle_timeout=10, hard_timeout=30)
    
    # If the packet is not handled by a flow, send it out as a packet_out to allow learning/flooding
    # This acts as a fallback for the very first packet of a flow before a flow rule is installed.
    msg = of.ofp_packet_out(data=packet.pack())
    msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
    event.connection.send(msg)


  def _handle_ConnectionUp (self, event):
    self.connection = event.connection
    log.info("Switch %s connected. Installing initial firewall rules." % dpid_to_str(event.dpid))

    # Install initial static L2 block rules
    for source_mac, dest_mac in self.l2_blocked_mac_pairs:
        match = of.ofp_match(dl_src=source_mac)
        if dest_mac:
            match.dl_dst = dest_mac
        self.install_flow(match, action_type=of.OFPAT_DROP, priority=65535, idle_timeout=0, hard_timeout=0)
        log.info("Installed initial static L2 block flow for MAC %s->%s (on switch %s)" % (source_mac, dest_mac, dpid_to_str(event.dpid)))

    # Re-install dynamic spoofing block rules
    for mac in self.blocked_macs:
        match = of.ofp_match(dl_src=mac, dl_type=pkt.ethernet.IP_TYPE)
        self.install_flow(match, action_type=of.OFPAT_DROP, priority=65535, idle_timeout=0, hard_timeout=0)
        log.info("Re-installed block flow for spoofing MAC %s on switch %s" % (mac, dpid_to_str(event.dpid)))
        
    # Install a lower priority default rule to flood or act as a learning switch
    self.install_flow(of.ofp_match(), action_type=of.OFPAT_OUTPUT, priority=1, idle_timeout=0, hard_timeout=0)
    log.info("Installed low-priority default forwarding rule for learning.")


def launch (l2config="l2firewall.config", l3config="l3firewall.config"):
  """
  Launches the Firewall module.
  """
  # Ensure config files exist with headers if they don't, to prevent IOError
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
