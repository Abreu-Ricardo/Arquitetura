#!/bin/bash

# ./perf_script.sh $(pidof a.out) $(pidof prog1) $(pidof prog2)
echo $1 $2 $3
FlameG='/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/FlameGraph'

echo "caminho aqui --> $FlameG"


# 436595 436596 436597

# Achar um jeito do sleep funcionar
# sudo perf record -p 339427,339428,339429 -a -g -F 99 sleep 10
#sudo perf record -p $1 -F 99 -a -g sleep 10 -o saida_1.data  & 
#sudo perf record -p $2 -F 99 -a -g sleep 10 -o saida_2.data  & 
#sudo perf record -p $3 -F 99 -a -g sleep 10 -o saida_3.data  &

sudo perf record -p $1,$2 -F 99 -a -g -- sleep 20  && sudo perf script | /home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/FlameGraph/stackcollapse-perf.pl > out.perf-folded;

/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/FlameGraph/flamegraph.pl out.perf-folded > perf.svg

sudo chown ricardo perf.svg

# TODO
# PROBLEMA --> ESSA LINHA DE CODIGO SOH GERA 1 perf.data
# criar outros 2 programas com funcoes diferentes para testar
#sudo perf record -F 99 -a -g -- sleep 10 -p $1,$2,$3 -o SAIDA.data
#sleep 15

#sudo cp perf.data saida_1.data 
#perf script | $FlameG/stackcollapse-perf.pl > out.perf-folded
#$FlameG/flamegraph.pl out.perf-folded > perf_1.svg
#
#rm out.perf-folded
#
#sudo cp saida_2.data perf.data
#perf script | $FlameG/stackcollapse-perf.pl > out.perf-folded
#$FlameG/flamegraph.pl out.perf-folded > perf_2.svg
#
#rm out.perf-folded
#
#sudo cp saida_3.data perf.data
#perf script | $FlameG/stackcollapse-perf.pl > out.perf-folded
#$FlameG/flamegraph.pl out.perf-folded > perf_3.svg
#
#rm out.perf-folded

#perf script | $FlameG/stackcollapse-perf.pl > out.perf-folded

#$FlameG/flamegraph.pl out.perf-folded > perf.svg

