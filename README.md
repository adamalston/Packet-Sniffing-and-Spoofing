# Packet Sniffing and Spoofing

[![License](https://img.shields.io/github/license/adamalston/Packet-Sniffing-and-Spoofing?color=black)](LICENSE)

Packet sniffing and spoofing are two evolving threats in network security. There are many packet sniffing and spoofing tools, such as Wireshark, tcpdump, netwox, etc. Some of these tools are widely used by security experts, as well as by attackers. Being able to use these tools is important, but what is more important in network security is to understand how these tools work, i.e., how packet sniffing and spoofing are implemented in software.

## Sniffing Packets

Below is a simple sniffer program which utilizes Scapy:

```Python
from scapy.all import *

print("SNIFFING PACKETS")

def print_pkt(pkt):
    print("Source IP:", pkt[IP].src)
    print("Destination IP:", pkt[IP].dst)
    print("Protocol:", pkt[IP].proto)
    print("\n")

pkt = sniff(filter='icmp', prn=print_pkt)
```

In the above code, for each captured packet, the callback function `print_pkt()` will be invoked; this function will print out some of the packet's info.

When sniffing packets, certain types of packets may be of heightened interest. It is possible to select only certain packets by setting filters when designing a sniffer. Scapy’s filtering uses the BPF (Berkeley Packet Filter) syntax.

Examples of filtering possible with Scapy include:

-   Capturing only ICMP packets
-   Capturing TCP packets that come from a particular IP and with a destination port number 37
-   Capturing packets that come from or go to a particular subnet such as `128.200.0.0/16`

## Spoofing Packets

As a packet spoofing tool, Scapy enables arbitrary values to be set in the fields of different packet headers. For example, IP spoofing can be used by a malicious party to invoke a DDoS attack against a target. IP spoofing is the creation of IP packets which have a modified source address to either conceal the identity of the sender, to impersonate another network entity (a computer system, a datacenter, etc.), or both.

**Spoof ICMP packet**

```python
from scapy.all import *

print("SENDING SPOOFED ICMP PACKET")

ip = IP(src="1.2.3.4", dst="93.184.216.34") # IP Layer
icmp = ICMP()                               # ICMP Layer
pkt = ip/icmp                               # Construct the complete packet
pkt.show()

send(pkt, verbose=0)
```

**Spoof UDP packets**

```python
from scapy.all import *

print("SENDING SPOOFED UDP PACKET")

ip = IP(src="1.2.3.4", dst="10.0.2.69") # IP Layer
udp = UDP(sport=8888, dport=9090)       # UDP Layer
data = "Hello UDP!\n"                   # Payload
pkt = ip/udp/data                       # Construct the complete packet
pkt.show()

send(pkt,verbose=0)
```

## Sniffing and then Spoofing

Combine the sniffing and spoofing techniques to implement a sniff-and-then-spoof program. **Need two VMs on the same LAN.** From VM A, ping an IP X. This action generates an ICMP echo request packet. If X is alive, the ping program will receive an echo reply, and print out the response. The sniff-and-then-spoof program runs on VM B, which monitors the LAN through packet sniffing. Whenever it sees an ICMP echo request, regardless of what the target IP address is, the program immediately sends out an echo reply using the packet spoofing technique. Therefore, regardless of whether machine X is alive or not, the ping program will always receive a reply, indicating that X is alive.

## Scapy actions

```python
IP()
IP().show()

IP()/ICMP()

p = IP()/ICMP()
p.show()
p = IP()/UDP()
p.show()

p = IP()/UDP()/"This is my UDP packet"
p.show()

send( IP()/UDP()/"This is my UDP packet" )

send( IP(dst='10.0.2.7')/UDP()/"This is my UDP packet" )
```

---

Thank you for your interest, this project was fun and insightful!
