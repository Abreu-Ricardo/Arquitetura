#!/bin/python3

import matplotlib.pyplot as plt


ida = open( "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/reply_ping/results/temp_sinal/ida.txt", 'r')
ida_linhas = ida.readlines()
#ida_linhas.sort()


idaVolta = open( "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/reply_ping/results/temp_sinal/idaVolta.txt", 'r')
idaVolta_linhas = idaVolta.readlines()
#idaVolta_linhas.sort()


# Define x values (from -10 to 10)
#x_values = list(range(5, 11))
x_values = list(range(0, 1000))

# Define y values for two lines
y1_values = [2  * x + 3 for x in x_values]   # Line 1: y = 2x + 3
y2_values = [-1 * x + 5 for x in x_values]  # Line 2: y = -x + 5

ida_linhas   = list(map(float, ida_linhas))
idaVolta_linhas = list(map(float, idaVolta_linhas))


# Plot both lines
plt.plot( x_values , ida_linhas   , 'r-'  , label="ida")  # 1
#plt.plot( x_values , idaVolta_linhas , 'k--' , label="idaVolta")  # 2
plt.plot( x_values , idaVolta_linhas , 'k-' , label="idaVolta")  # 2

#plt.ylim(auto=True)
#plt.yticks([0.01, 0.02, 0.03, 0.04, 0.05, 0.06 , 0.07, 0.08, 0.09])
#plt.yticks([min(ida_linhas), max(udp_linhas)])

# Customize plot
plt.xlabel("Número-pkts")
plt.ylabel("Latência-us")
plt.title("Latência do sinal(1000 pkts) entre kernel-C3 e kernel-C1")
plt.grid(True, linestyle='--', linewidth=0.4)
plt.legend()

# Show plot
plt.show()

