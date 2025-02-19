#!/bin/bash

# ./perf_script.sh $(pidof a.out) $(pidof prog1) $(pidof prog2)

procs=$1,$2,$3,$4,$5,$6,$7,$8,$9,${10}

echo -e "$procs \n\n" 
echo $1,$2,$3,$4,$5,$6,$7,$8,$9,${10}

FlameG='/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/FlameGraph'

#echo "caminho aqui --> $FlameG"


# IMPORTANTE -o N FUNCIONA
# O limite de parametros do bash com $ sao 9 PARAMETROS, acima disso tem que ser com chave ${10}, ${11} e ${12}
sudo perf record -p $procs -F 99 -a -g sleep 20  && sudo perf script | sudo /home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/FlameGraph/stackcollapse-perf.pl > out.perf-folded;

sudo /home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/FlameGraph/flamegraph.pl out.perf-folded > perf.svg

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

