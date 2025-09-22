#!/bin/bash

sudo ip netns exec c1 sh -c "mount -t debugfs none /sys/kernel/debug"

sudo ip netns exec c1 sh -c "source init_containers.sh"
sudo ip netns exec c2 sh -c "source init_containers.sh"
sudo ip netns exec c3 sh -c "source init_containers.sh"
sudo ip netns exec c4 sh -c "source init_containers.sh"



