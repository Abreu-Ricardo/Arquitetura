#!/bin/python3
import matplotlib.pyplot as plt
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

# Define x values (from -10 to 10)
#x_values = list(range(5, 11))
x_values = list(range(0, 1000))

# Define y values for two lines
y1_values = [2  * x + 3 for x in x_values]   # Line 1: y = 2x + 3
y2_values = [-1 * x + 5 for x in x_values]  # Line 2: y = -x + 5

poll_linhas   = list(map(float, poll_linhas))
signal_linhas = list(map(float, signal_linhas))
udp_linhas    = list(map(float, udp_linhas))
rot_linhas    = list(map(float, rot_linhas))
skmsg_linhas  = list(map(float, skmsg_linhas))
sk_sig_linhas = list(map(float, sk_sig_linhas))


# Plot both lines
#plt.plot( x_values , poll_linhas   ,  'r-'   , label="Polling")  # 1
#plt.plot( x_values , signal_linhas ,  'k-'   , label="Signal")  # 2
#plt.plot( x_values , udp_linhas    ,  'b-'   , label="UDP + polling") # 3
#plt.plot( x_values , rot_linhas    ,  'y-'   , label="Routing") # 4
#plt.plot( x_values , skmsg_linhas  ,  'g-'   , label="sk_msg + polling") # 5
#plt.plot( x_values , sk_sig_linhas ,  'g--'  , label="skmsg + signal") # 6
#plt.plot(x_values, y2_values, 'b-', label="y = -x + 5")  # Blue line

poll_sorted = np.sort(poll_linhas)
poll_cdf    = np.arange(1, len(poll_sorted) + 1) / len(poll_sorted)

signal_sorted = np.sort(signal_linhas)
signal_cdf    = np.arange(1, len(signal_sorted) + 1) / len(signal_sorted)

udp_sorted = np.sort(udp_linhas)
udp_cdf    = np.arange(1, len(udp_sorted) + 1) / len(udp_sorted)

rot_sorted = np.sort(rot_linhas)
rot_cdf    = np.arange(1, len(rot_sorted) + 1) / len(rot_sorted)

skmsg_sorted = np.sort(skmsg_linhas)
skmsg_cdf    = np.arange(1, len(skmsg_sorted) + 1) / len(skmsg_sorted)

sksig_sorted = np.sort(sk_sig_linhas)
sksig_cdf    = np.arange(1, len(sksig_sorted) + 1) / len(sksig_sorted)


#data = np.random.randn(1000)
y = np.arange(1000) / float(1000)

plt.plot(poll_sorted     , y ,'r-' , linewidth = 3 , label="Poll")
plt.plot(signal_sorted   , y ,'k-' , linewidth = 3 , label="Signal")
plt.plot(udp_sorted      , y ,'b-' , linewidth = 3 , label="UDP")
plt.plot(rot_sorted      , y ,'y-' , linewidth = 3 , label="Routing")
plt.plot(skmsg_sorted    , y ,'g-' , linewidth = 3 , label="SK_MSG")
plt.plot(sksig_sorted    , y ,'g--', linewidth = 3 , label="SK_MSG + Signal")

'''
plt.plot(poll_sorted   , y , marker='.', linestyle='none', label="Poll")
plt.plot(signal_sorted , y , marker='.', linestyle='none', label="Signal")
plt.plot(udp_sorted    , y , marker='.', linestyle='none', label="UDP")
plt.plot(rot_sorted    , y , marker='.', linestyle='none', label="Routing")
plt.plot(skmsg_sorted  , y , marker='.', linestyle='none', label="SK_MSG")
plt.plot(sksig_sorted  , y , marker='.', linestyle='none', label="SK_MSG + Signal")
'''
'''
poll_cdf  
signal_cdf
udp_cdf   
rot_cdf   
skmsg_cdf 
sksig_cdf 
'''

#plt.ylim(auto=True)
#plt.yticks([0.01, 0.02, 0.03, 0.04, 0.05, 0.06 , 0.07, 0.08, 0.09])
#plt.yticks([min(poll_linhas), max(udp_linhas)])

# Customize plot
plt.xlabel("Latency-ms", fontsize=20)
plt.ylabel("Percent"   , fontsize=20)

#plt.xticks([0.00, 0.01, 0.02, 0.03, 0.04] ,fontsize=20)
plt.xticks(fontsize=20)
plt.yticks(fontsize=19)

#plt.locator_params(axis='x', nbins=15)
#plt.title("Latência dos pkts(1000) entre versões")
#plt.axhline(0, color='black', linewidth=0.5)  # X-axis
#plt.axvline(0, color='black', linewidth=0.5)  # Y-axis
plt.grid(True, linestyle='--', linewidth=0.4)
plt.legend()

# Show plot
plt.show()

