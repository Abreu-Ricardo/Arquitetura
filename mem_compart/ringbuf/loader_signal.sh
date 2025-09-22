#!/bin/bash

target=${1}

echo -e "Enviando sinal SIGRTMIN+1 para o pid $target"

for i in {1..100000}; do
        echo -e "Enviando sinal $i..."
        sudo kill -q 777 -SIGRTMIN+1 $target
done


