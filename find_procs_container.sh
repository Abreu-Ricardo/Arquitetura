#!/bin/bash

#mac1=$(cat /sys/class/net/veth1/address)
#mac2=$(cat /sys/class/net/veth8/address)
#echo -e "valor do mac1: $mac1 | valor do mac2: $mac2"

if [ -z $1 ];then
    echo "Passe o pid do container: sudo $0 <PID>"
    exit
fi

echo $pid
# List all network namespaces
echo -e "Listando os namespaces ativos..."
ip netns list

# Show namespace processes using /proc
#ls -l /proc/$1/ns/net

# Get namespace inode number
echo -e "\nInode do namespace..."
ls -l /proc/$1/ns/net | awk '{print $NF}' | cut -d '-' -f 2

echo -e "\nProcessos que estao no NS passado..."
# Find all processes in the same namespace
for pid in /proc/[0-9]*; do
    if [ "$(readlink $pid/ns/net)" = "$(readlink /proc/$1/ns/net)" ]; then
        echo "Process $pid"
    fi
done
