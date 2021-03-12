#!/bin/bash

echo '[*] checking IP forwarding'

nmap -sn -n $1 --script ip-forwarding --script-args="ip-forwarding.target=$3" > /tmp/ip_forwarding.log
if grep -q 'ip forwarding enabled' /tmp/ip_forwarding.log; then
	cat /tmp/ip_forwarding.log
	led red on > /dev/null
fi

