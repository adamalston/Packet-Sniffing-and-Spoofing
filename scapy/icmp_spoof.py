from scapy.all import *

print("SENDING SPOOFED ICMP PACKET")

ip = IP(src="1.2.3.4", dst="93.184.216.34") # IP Layer
icmp = ICMP()                               # ICMP Layer
pkt = ip/icmp                               # Construct the complete packet
pkt.show()

send(pkt, verbose=0)
