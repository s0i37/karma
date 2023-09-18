#!/bin/bash

WAIT=2
DPORT=445
#https://github.com/worawit/MS17-010

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] checking MS17-010'
	nmap -Pn -n -p 445 --script smb-vuln-ms17-010 $1 > /tmp/ms17-010.log 2> /dev/null
	grep 'State: VULNERABLE' /tmp/ms17-010.log --color=auto && led red on 2> /dev/null
fi