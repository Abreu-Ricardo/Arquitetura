#!/bin/python3

from statistics import *

ARQUIVO1 = open("/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/reply_ping/results/temp_sinal/sinal_ida_e_volta_us_CERTO.txt")
ARQUIVO2 = open("/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/reply_ping/results/temp_sinal/sinal_soh_ida.txt")

idaEvolta = ARQUIVO1.readlines()
ida       = ARQUIVO2.readlines()

int_idaEvolta = list(map(float, idaEvolta))
int_ida       = list(map(float, ida))

media_idaEvolta  = mean(int_idaEvolta)
media_ida        = mean(int_ida)

desvio_idaEvolta = []
desvio_ida       = []


# Media dos tempos em us de envio e recebimento do sinal
# do kernel para o usuario na mesma CPU
print(f"Media do tempo de ida: {mean(int_ida)}\nMedia das do tempo de ida e volta: {mean(int_idaEvolta)}\n")

for i in int_idaEvolta:
    # getting deviation
    desvio_idaEvolta.append(abs(i - media_idaEvolta))

for i in int_ida:
    # getting deviation
    desvio_ida.append(abs(i - media_ida))

print(f"Desvio da ida e volta: {stdev(int_idaEvolta):.3f}\nDesvio da ida: {stdev(int_ida):.3f}");

