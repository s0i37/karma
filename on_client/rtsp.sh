#!/bin/bash

WAIT=2
DPORT=554

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] RTSP streaming'
	nmap -Pn -n -p 554 --script rtsp-methods $1
	nmap -Pn -n -p 554 --script rtsp-url-brute $1 -oX /tmp/rtsp.xml > /dev/null 2>&1
	if url=$(cat /tmp/rtsp.xml | xmllint --xpath '//table[@key="discovered"]/elem/text()' - 2>/dev/null)
	then
		echo "[*] $url"
		timeout 20 cvlc "$url" --sout=file/ts:/tmp/$1.mpg > /dev/null 2>&1
	fi
	if [ -s "/tmp/$1.mpg" ]; then
		cp "/tmp/$1.mpg" "$1.mpg"
		echo "[+] $(ls -lh $1.mpg)"
	fi
fi
