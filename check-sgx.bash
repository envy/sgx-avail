#!/bin/bash

CPUID=`cpuid -1 -r | grep "0x00000007 0x00" | awk '{ print $4 }'`
HEX=${CPUID:6}
N=$((16#$HEX))
((($N & 0x4) == 4)) && exit 0 || exit 1
