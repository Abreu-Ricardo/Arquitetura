#!/bin/bash


string="$1"

if [ -z $1 ]; then
    echo -e "Passe o comando <up/down>: $0 up/down \n"
fi


if [ "$string" = "up" ]; then

    echo -e "Desabilitando modo boost da CPU..."
    echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost

    echo -e "Travando o clock em  3.6GHz..."
    sudo cpupower -c 0-11 frequency-set -d 3.6GHz -u 3.6GHz

    # Manter o clock estavel
    echo -e "Colocando o governor em perfermance"
    sudo cpupower -c 0-11 frequency-set -g performance

    exit 0
fi

if [ "$string" = "down" ]; then

    echo -e "Habilitando modo boost da CPU..."
    echo 1 | sudo tee /sys/devices/system/cpu/cpufreq/boost

    echo -e "Destravando o clock em  2.2-4.2GHz..."
    sudo cpupower -c 0-11 frequency-set -d 2.2GHz -u 4.2GHz

    sudo cpupower -c 0-11 frequency-set -g ondemand

    exit 0

fi
