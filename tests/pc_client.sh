#!/bin/bash
for port in `seq 50000 51000`;
do
    echo "aaaa" > /tmp/$port
    mkfifo dummy$port
    #cat /tmp/$port dummy | netcat -v 192.168.1.1 $port &
    cat /tmp/$port dummy | netcat -v 47.92.141.202 $port &
done
exit 0
