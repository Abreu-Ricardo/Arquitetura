#!/bin/python3
import matplotlib.pyplot as plt


xsk1 = open("xsk1-1c.txt", 'r')
xsk1_linhas   = xsk1.readlines()

xsk2 = open("xsk2-2c.txt", 'r')
xsk2_linhas   = xsk2.readlines()

app_1cont = open("server-1c.txt", 'r')
app1c     = app_1cont.readlines()

app_2cont = open("server-2c.txt", 'r')
app2c     = app_2cont.readlines()

#rot = open( "roteamento.txt", 'r')
#rot_linhas = rot.readlines()
#
#skmsg_signal = open( "skmsg+signal.txt", 'r')
#sk_sig_linhas = skmsg_signal.readlines()

# Define x values (from -10 to 10)
#x_values = list(range(5, 11))
x_values = list(range(0, 1000))

# Define y values for two lines
y1_values = [2  * x + 3 for x in x_values]   # Line 1: y = 2x + 3
y2_values = [-1 * x + 5 for x in x_values]  # Line 2: y = -x + 5

xsk1_linhas     = list(map(float, xsk1_linhas))
xsk2_linhas     = list(map(float, xsk2_linhas))
app1c           = list(map(float, app1c))
app2c           = list(map(float, app2c))
#skmsg_linhas  = list(map(float, skmsg_linhas))
#sk_sig_linhas = list(map(float, sk_sig_linhas))


# Plot both lines
#plt.plot( x_values , xsk1_linhas   ,  'r-'   , label="1 xsk 1 container")  # 1
plt.plot( x_values , xsk2_linhas  ,  'k-'  , label="2 xsk 2 containers")   # 2
#plt.plot( x_values , app1c       ,  'b-'   , label="App 1 container")    # 3
plt.plot( x_values , app2c       ,  'y-'   , label="App 2 containers")    # 4

#plt.ylim(auto=True)
#plt.yticks([0.01, 0.02, 0.03, 0.04, 0.05, 0.06 , 0.07, 0.08, 0.09])
#plt.yticks([min(poll_linhas), max(udp_linhas)])


# Customize plot
plt.xlabel("Número-pkts")
plt.ylabel("Latência-ms")
plt.title("Latência dos pkts(1000) usando gerador UDP 50ms de CARGA")
#plt.axhline(0, color='black', linewidth=0.5)  # X-axis
#plt.axvline(0, color='black', linewidth=0.5)  # Y-axis
plt.grid(True, linestyle='--', linewidth=0.4)
plt.legend()

# Show plot
plt.show()

