#!/bin/python3

import matplotlib.pyplot as plt

# Data for the bar chart
categories = ["Polling", "Signal", "UDP"]
values = [200, 0.01, 101]

# Create the bar chart
plt.bar(categories, values, color='gray', hatch="x")


# Labels and title
plt.xlabel("Método")
plt.ylabel("% do uso de CPU")
plt.title("Uso de CPU em 1000pkts")
plt.grid(True, which='major', axis='y', linestyle='--', linewidth=0.7)

# Show the graph
plt.show()

