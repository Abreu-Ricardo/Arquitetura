#!/bin/python3

import matplotlib.pyplot as plt


poll = open( "poll.txt", 'r')
poll_linhas = poll.readlines()
#poll_linhas.sort()


signal = open( "signal.txt", 'r')
signal_linhas = signal.readlines()
#signal_linhas.sort()

udp = open( "udp.txt", 'r')
udp_linhas = udp.readlines()
#udp_linhas.sort()

#skmsg = open( "skmsgpoll_limpo.txt", 'r')
#skmsg_linhas = skmsg.readlines()

#rot = open( "roteamento.txt", 'r')
#rot_linhas = rot.readlines()

# Define x values (from -10 to 10)
#x_values = list(range(5, 11))
x_values = list(range(0, 1000))

# Define y values for two lines
y1_values = [2  * x + 3 for x in x_values]   # Line 1: y = 2x + 3
y2_values = [-1 * x + 5 for x in x_values]  # Line 2: y = -x + 5

poll_linhas   = list(map(float, poll_linhas))
signal_linhas = list(map(float, signal_linhas))
udp_linhas    = list(map(float, udp_linhas))
#rot_linhas    = list(map(float, rot_linhas))
#skmsg_linhas  = list(map(float, skmsg_linhas))


# Plot both lines
plt.plot( x_values , poll_linhas   , 'r-'   , label="poll")  # 1
plt.plot( x_values , signal_linhas , 'k-'   , label="signal")  # 2
plt.plot( x_values , udp_linhas    , 'b-'   , label="UDP") # 3
#plt.plot( x_values , rot_linhas    , 'y-'   , label="Roteamento") # 4
#plt.plot( x_values , skmsg_linhas  , 'g-'   , label="sk_msg") # 5
#plt.plot(x_values, y2_values, 'b-', label="y = -x + 5")  # Blue line

#plt.ylim(auto=True)
#plt.yticks([0.01, 0.02, 0.03, 0.04, 0.05, 0.06 , 0.07, 0.08, 0.09])
#plt.yticks([min(poll_linhas), max(udp_linhas)])


# Customize plot
plt.xlabel("Número-pkts")
plt.ylabel("Latência-ms")
plt.title("Latência dos pkts(1000) usando as funções como lib")
#plt.axhline(0, color='black', linewidth=0.5)  # X-axis
#plt.axvline(0, color='black', linewidth=0.5)  # Y-axis
plt.grid(True, linestyle='--', linewidth=0.4)
plt.legend()

# Show plot
plt.show()

