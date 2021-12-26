#!/bin/bash

echo '[*] HTTP cleartext monitoring'

rm /tmp/ngrep.log
ngrep -d "$1" -i 'cookie|passw|token' 'port 80 or port 8080' 2>&1 > /tmp/ngrep.log &

tail -f /tmp/ngrep.log | while read line
do
	echo "$line" | grep -v '^match:' | grep -ai -e cookie -e passw -e token --color=auto
done