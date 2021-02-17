#!/bin/bash

echo 'SSL splitting'

[[ $(pgrep sslsplit) = '' ]] && {
 screen -dmS sslsplit sslsplit -k key.pem -c cert.pem -l con.log -L data.log -P autossl 0.0.0.0 1080
}