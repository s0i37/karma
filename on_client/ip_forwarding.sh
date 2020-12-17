#!/bin/bash

echo 'checking IP forwarding'

nmap -sn -n $1 --script ip-forwarding --script-args="ip-forwarding.target=$3"
