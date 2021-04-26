#!/usr/bin/python
from nmb.NetBIOS import NetBIOS # pip install pysmb
from sys import argv

print('[*] getting network interfaces via NetBIOS')

ip = argv[1]
netbios = NetBIOS()

def interfaces(ip):
	try:
		netbios_names = netbios.queryIPForName( str(ip), timeout=0.1 )
		if netbios_names:
			print(', '.join( (netbios.queryName( netbios_names[0], ip=str(ip) ) or []) + netbios_names ))
	except Exception as e:
		print(str(e))

interfaces(ip)
