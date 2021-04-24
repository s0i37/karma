#!/usr/bin/python3
from scapy.all import *
from sys import argv


pcap = argv[1]

for packet in rdpcap(pcap):
	if IP in packet:
		if packet[IP].ttl == 128:
			print(pcap)
			print(packet.summary())
			break
