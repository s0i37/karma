#!/bin/bash

echo 'writing trafic'

tcpdump -i $2 -nn -w "$1.pcap"
