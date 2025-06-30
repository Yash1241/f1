sudo mn --topo=single,4 --mac --controller=remote,port=6655 --switch=ovsk
*** Creating network
*** Adding controller
*** Adding hosts:
h1 h2 h3 h4
*** Adding switches:
s1
*** Adding links:
(h1, s1) (h2, s1) (h3, s1) (h4, s1)
*** Configuring hosts
h1 h2 h3 h4
*** Starting controller
c0
*** Starting 1 switches
s1
*** Starting CLI:
mininet>


/////////////////////////////////////////////////////
  ubuntu@ubuntu:~ $
mininet> h1 ifconfig h1-eth0 192.168.2.10/24
mininet> h2 ifconfig h2-eth0 192.168.2.20/24
mininet> h3 ifconfig h3-eth0 192.168.2.30/24
mininet> h4 ifconfig h4-eth0 192.168.2.40/24
mininet> h1 hping3 192.168.2.20 -c 1000 -s 0 --flood --rand-source
hping 192.168.2.20 (lo 192.168.2.20): S set, 40 headers
HPING 192.168.2.20 (lo 192.168.2.20): S set, 40 headers 0 data bytes
hping in flood mode, no replies will be shown
/////////////////////////////////////////////////////////////
ubuntu@ubuntu:~$ sudo python /home/ubuntu/pox/pox.py openflow.of_01 --port=6655 pox.forwarding.L3Firewall --l2config=/home/ubuntu/pox/pox/forwarding/l2firewall.config --l3config=/home/ubuntu/pox/pox/forwarding/l3firewall.config
POX 0.5.0 (eel) is up.
INFO:Initializing L3Firewall module...
INFO:L2 firewall config header: id,mac_0,mac_1
INFO:Loading L2 firewall rules from /home/ubuntu/pox/pox/forwarding/l2firewall.config
INFO:Loaded 0 L2 firewall rules.
INFO:Attempting to load L3 firewall rules from /home/ubuntu/pox/pox/forwarding/l3firewall.config (currently empty).
INFO:Switch 00-00-00-00-00-00-00-01 connected. Installing initial firewall rules.
INFO:Installed low-priority default forwarding rule for learning
  //////////////////////////////////////////

mininet> h3 ping -c 1 192.168.2.40
PING 192.168.2.40 (192.168.2.40) 56(84) bytes of data.
64 bytes from 192.168.2.40: icmp_seq=1 ttl=64 time=0.045 ms

--- 192.168.2.40 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.045/0.045/0.045/0.000 ms
mininet>

/////////////////////////////////////////
mininet> h1 hping3 192.168.2.20 -c 10000 -S --flood --rand-source -V
HPING 192.168.2.20 (h1-eth0 192.168.2.20): S set, 40 headers + 0 data bytes
hping in flood mode, no replies will be shown
^C
////////////////////////////////////////////////////
  INFO:Port security: Learned MAC 00:00:00:00:00:01 -> IP 192.168.2.10
WARNING:!!! SPOOFING DETECTED !!! MAC 00:00:00:00:00:01 (original IP: 192.168.2.10) is now using IP 47.244.102.57
INFO:Blocking future IP traffic from spoofing MAC: 00:00:00:00:00:01
WARNING:!!! SPOOFING DETECTED !!! MAC 00:00:00:00:00:01 (original IP: 192.168.2.10) is now using IP 143.208.124.56
INFO:Blocking future IP traffic from spoofing MAC: 00:00:00:00:00:01
DEBUG:Installing DROP flow for match: dl_src=00:00:00:00:00:01,dl_type=0x800
////////////////////////////////////////////////

mininet> ovs-ofctl dump-flows s1
NXST_FLOW reply (xid=0x4):
 cookie=0x0, duration=X.YYYs, table=0, n_packets=Z, n_bytes=W, idle_timeout=0, hard_timeout=0, priority=30000,dl_src=00:00:00:00:00:01,dl_type=0x800 actions=drop
 cookie=0x0, duration=A.BBBs, table=0, n_packets=C, n_bytes=D, idle_timeout=10, hard_timeout=30, priority=1000,tcp,tp_dst=80,nw_src=192.168.2.10,nw_dst=192.168.2.20 actions=output:2
 cookie=0x0, duration=E.FFFs, table=0, n_packets=G, n_bytes=H, priority=1 actions=NORMAL

////////////////////////////////////////////


mininet> h1 ping -c 4 192.168.2.20
PING 192.168.2.20 (192.168.2.20) 56(84) bytes of data.

--- 192.168.2.20 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3006ms
mininet>

////////////////////////////////////////////////////////////////
 h3 ping -c 1 192.168.2.40
PING 192.168.2.40 (192.168.2.40) 56(84) bytes of data.
64 bytes from 192.168.2.40: icmp_seq=1 ttl=64 time=0.043 ms

--- 192.168.2.40 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.043/0.043/0.043/0.000 ms
mininet>

///////////////////////////////////////////////////////////////////////

