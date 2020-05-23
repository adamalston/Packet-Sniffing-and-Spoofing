# Packet Sniffing and Spoofing

![License](https://img.shields.io/github/license/adamalston/Packet-Sniffing-and-Spoofing?color=9cf&style=flat-square) [![HitCount](http://hits.dwyl.com/adamalston/Packet-Sniffing-and-Spoofing.svg)](http://hits.dwyl.com/adamalston/Packet-Sniffing-and-Spoofing)

Packet sniffing and spoofing are two important concepts in network security. They also represent threats to network communication. Being able to understand these two threats is essential for understanding security measures in networking. There are many packet sniffing and spoofing tools, such as Wireshark, tcpdump, netwox, etc. Some of these tools are widely used by security experts, as well as by attackers. Being able to use these tools is important, but what is more important in network security is to understand how these tools work, i.e., how packet sniffing and spoofing are implemented in software.

## Sniffing Packets

Use Scapy to do packet sniffing in Python programs.

Below is a simple sniffer program (`sniff.py`) written using python/scapy:
```Python
from scapy.all import *

print("SNIFFING PACKETS")

def print_pkt(pkt):                       
   print("Source IP:", pkt[IP].src)
   print("Destination IP:", pkt[IP].dst)
   print("Protocol:", pkt[IP].proto)
   print("\n")

pkt = sniff(filter='icmp',prn=print_pkt)   
```
Run the program as like any other python program. Scapy may need to be installed for python3 in the VM.
```
// Run the program with root privileges
$ sudo python sniff.py
```
For scapy to work correctly, Python must be run using `sudo` (root privileges).

In the above code, for each captured packet, the callback function `print_pkt()` will be invoked; this function will print out some of the information about the packet. Run the program with root privileges and demonstrate that it can indeed capture packets. After that, run the program again, but _without_ root privileges. Observe what happens.

Usually, when sniffing packets, certain types of packets are of interest. It is possible to select only certain packets by setting filters when designing the sniffer. Scapy’s filtering uses the BPF (Berkeley Packet Filter) syntax.

Next, try to set the following filters to demonstrate that the sniffer program works with each _(each filter should be set separately)_:
- Capture only ICMP packets
- Capture TCP packets that comes from a particular IP and with a destination port number 23.
- Capture packets that come from or go to a particular subnet. <br/> (Pick any subnet, such as `128.230.0.0/16`; do not pick the subnet that the VM is attached to.)

---
## Spoofing Packets

As a packet spoofing tool, Scapy enables us to set the fields of (IP) packets to arbitrary values. The objective here is to spoof IP packets with an arbitrary source IP address. More specifically, spoof ICMP echo request packets, and send them to another VM on the same network. Then, use Wireshark to observe whether the ICMP echo request will be accepted by the receiver. If it is accepted, an echo reply packet will be sent to the spoofed IP address.

Make use of `IP()` and `ICMP()` objects within Scapy, as well as the packet layering operator `/` to construct and send an IP packet that contains an ICMP packet. Look at packet object `p` using `p.show` or `ls(p)`.

**Spoof ICMP packet**

```python
from scapy.all import *

print("SENDING SPOOFED ICMP PACKET")

ip = IP(src="1.2.3.4", dst="93.184.216.34")
icmp = ICMP()
pkt = ip/icmp
pkt.show()

send(pkt,verbose=0)
```

**Spoof UDP packets**

```python
from scapy.all import *

print("SENDING SPOOFED ICMP PACKET")

ip = IP(src="1.2.3.4", dst="10.0.2.69") # IP Layer
udp = UDP(sport=8888, dport=9090)       # UDP Layer
data = "Hello UDP!\n"                   # Payload
pkt = ip/udp/data                       # Construct the complete packet
pkt.show()

send(pkt,verbose=0)
```

---

## Sniffing and then Spoofing

Combine the sniffing and spoofing techniques to implement a sniff-and-then-spoof program. **Need two VMs on the same LAN.** From VM A, ping an IP X. This will generate an ICMP echo request packet. If X is alive, the ping program will receive an echo reply, and print out the response. The sniff-and-then-spoof program runs on VM B, which monitors the LAN through packet sniffing. Whenever it sees an ICMP echo request, regardless of what the target IP address is, the program should immediately send out an echo reply using the packet spoofing technique. Therefore, regardless of whether machine X is alive or not, the ping program will always receive a reply, indicating that X is alive.

---

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

Thank you for your interest, this project was a fun to work on!