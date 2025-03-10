#!/bin/python3


import matplotlib.pyplot as plt
import numpy as np



def merge_unique(arr1, arr2):
    return list(set(arr1) | set(arr2))  # Union of two sets


poll = open( "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/reply_ping/results/results_100pkts/poll.txt", 'r')
poll_linhas = poll.readlines()
#poll_linhas.sort()


signal = open( "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/reply_ping/results/results_100pkts/signal.txt", 'r')
signal_linhas = signal.readlines()
#signal_linhas.sort()

udp = open( "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/reply_ping/results/results_100pkts/udp.txt", 'r')
udp_linhas = udp.readlines()
#udp_linhas.sort()

roteamento = open( "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/reply_ping/results/results_100pkts/roteamento.txt", 'r')
roteamento_linhas = roteamento.readlines()
#udp_linhas.sort()


t = merge_unique(poll_linhas, signal_linhas)
t = merge_unique(t, udp_linhas)
t.sort()
#print(t)

x_values = list(range(0, 100))
#x_values = list(np.arange(0, 0.100, 0.001))

# Define y values for two lines
#y1_values = [2  * x + 3 for x in x_values]   # Line 1: y = 2x + 3
#y2_values = [-1 * x + 5 for x in x_values]  # Line 2: y = -x + 5

#y1 = [ for i in poll_linhas]
y1 = []
y2 = []
y3 = []

for i in poll_linhas:
    for j in range(0, len(t)):
        if i == t[j]:
            y1.append(i)

for i in signal_linhas:
    for j in range(0, len(t)):
        if i == t[j]:
            y2.append(i)

for i in udp_linhas:
    for j in range(0, len(t)):
        if i == t[j]:
            y3.append(i)





y1 = list(map(float, y1))
y2 = list(map(float, y2))
y3 = list(map(float, y3))

poll_linhas = list(map(float, poll_linhas))
signal_linhas = list(map(float, signal_linhas))
udp_linhas = list(map(float, udp_linhas))
roteamento_linhas = list(map(float, roteamento_linhas))

#plt.yticks(sorted(set(yt)))
#plt.ylim(min(yt) , max(yt) )

# Plot both lines
plt.plot( x_values , poll_linhas       , 'r-'        , label="poll")        # 1
plt.plot( x_values , signal_linhas     , 'k--'        , label="signal")      # 2
plt.plot( x_values , udp_linhas        , 'b-'        , label="UDP")         # 3
plt.plot( x_values , roteamento_linhas , 'o-'        , label="Roteamento")  # 4
#plt.plot(x_values, y2_values, 'b-', label="y = -x + 5")  # Blue line


#plt.ylim(min(t), max(t))
#plt.yticks([min(poll_linhas), max(udp_linhas)])

#plt.ylim(min(yt) , max(yt))

# Customize plot
plt.xlabel("Número-pkts")
plt.ylabel("Latência(ms)")
plt.title("Latência dos pkts(100) entre versões")
#plt.axhline(0, color='black', linewidth=0.5)  # X-axis
#plt.axvline(0, color='black', linewidth=0.5)  # Y-axis
plt.grid(True, linestyle='--', linewidth=0.4)
plt.legend()

# Show plot
plt.show()

