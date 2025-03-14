#!/bin/python3

import matplotlib.pyplot as plt

# Data for the bar chart
categories = ["Polling", "Signal", "UDP"]
values = [200, 101, 101]

# Create the bar chart
plt.bar(categories, values, color='gray')

# Labels and title
plt.xlabel("Método")
plt.ylabel("% do uso de CPU")
plt.title("Uso de CPU em 1000pkts")

# Show the graph
plt.show()

