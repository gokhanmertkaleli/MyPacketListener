import scapy.all as scapy
from scapy_http import http

def listen_packets(interface):
    scapy.sniff(iface=interface,store=False,prn=analyze_packets)
    #callback function = prn

def analyze_packets(packet):
    packet.show

listen_packets("eth0")    