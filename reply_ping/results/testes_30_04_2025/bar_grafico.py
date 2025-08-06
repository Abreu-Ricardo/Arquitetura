#!/bin/python3
import matplotlib.pyplot as plt
import statistics
import numpy as np


poll = open( "poll.txt", 'r')
poll_linhas = poll.readlines()

signal = open( "sinal_isolado.txt", 'r')
#signal = open( "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/reply_ping/results/signal.txt", 'r')
#signal = open( "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/reply_ping/results/signal_ping.txt", 'r')
signal_linhas = signal.readlines()

udp = open( "udp.txt", 'r')
#udp = open( "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/reply_ping/results/udp_ping.txt", 'r')
udp_linhas = udp.readlines()

skmsg = open( "skmsgpoll_limpo.txt", 'r')
skmsg_linhas = skmsg.readlines()

rot = open( "roteamento.txt", 'r')
rot_linhas = rot.readlines()

skmsg_signal = open( "skmsg+signal.txt", 'r')
sk_sig_linhas = skmsg_signal.readlines()
#######################################################################

# Define x values (from -10 to 10)
#x_values = list(range(5, 11))
#x_values = list(range(0, 1000))

poll_linhas   = list(map(float, poll_linhas))
signal_linhas = list(map(float, signal_linhas))
udp_linhas    = list(map(float, udp_linhas))
rot_linhas    = list(map(float, rot_linhas))
skmsg_linhas  = list(map(float, skmsg_linhas))
sk_sig_linhas = list(map(float, sk_sig_linhas))


calls = ['Polling', 'Routing','UDP+polling', 'Signal', 'skmsg+poll ', ' skmsg+sig']
cycles = [ statistics.mean(poll_linhas), statistics.mean(rot_linhas), statistics.mean(udp_linhas),  statistics.mean(signal_linhas),  statistics.mean(skmsg_linhas), statistics.mean(sk_sig_linhas) ]

std_dev_poll   = np.std(poll_linhas)
std_dev_signal = np.std(signal_linhas)
std_dev_udp    = np.std(udp_linhas)
std_dev_rot    = np.std(rot_linhas)
std_dev_skmsg  = np.std(skmsg_linhas)
std_dev_sksig  = np.std(sk_sig_linhas)

std_devs = [
    std_dev_poll,
    std_dev_rot,
    std_dev_udp,
    std_dev_signal,
    std_dev_skmsg,
    std_dev_sksig
]

plt.bar(calls, cycles, yerr=std_devs, hatch="x" ,color='skyblue', width=0.6, edgecolor='navy', linewidth=1, 
        error_kw={'elinewidth': 2, # thickness of the error bar
        'ecolor': 'black', # color of the error bar
        'capsize': 8,      # override capsize here (optional)
        'capthick': 2,     # thickness of the cap line
        'linestyle': '--'  # style of the error bar line
    })


# Set bar color
# Adjust bar width
# Border color
# Border thickness# Plot both lines

#plt.plot( x_values , poll_linhas   ,  'r-'   , label="Polling")  # 1
#plt.plot( x_values , signal_linhas ,  'k-'   , label="Signal")  # 2
#plt.plot( x_values , udp_linhas    ,  'b-'   , label="UDP + polling") # 3
#plt.plot( x_values , rot_linhas    ,  'y-'   , label="Routing") # 4
#plt.plot( x_values , skmsg_linhas  ,  'g-'   , label="sk_msg + polling") # 5
#plt.plot( x_values , sk_sig_linhas ,  'g--'  , label="skmsg + signal") # 6
#plt.plot(x_values, y2_values, 'b-', label="y = -x + 5")  # Blue line

#plt.ylim(auto=True)
#plt.yticks([0.01, 0.02, 0.03, 0.04, 0.05, 0.06 , 0.07, 0.08, 0.09])
#plt.yticks([min(poll_linhas), max(udp_linhas)])


# Customize plot
#plt.xlabel("", fontsize=20)
plt.ylabel("Latency-ms", fontsize=25)

plt.xticks(fontsize=30)
plt.yticks(fontsize=30)

#plt.locator_params(axis='x', nbins=5)
#plt.title("Latência dos pkts(1000) entre versões")
#plt.axhline(0, color='black', linewidth=0.5)  # X-axis
#plt.axvline(0, color='black', linewidth=0.5)  # Y-axis
plt.grid(True, linestyle='--', linewidth=0.4)
#plt.legend()

# Show plot
plt.show()

