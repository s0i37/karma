#!/bin/bash

if [ x$(which led) != "x" ]; then
	led blue on 2> /dev/null
	sleep 10
	led blue off 2> /dev/null
fi
