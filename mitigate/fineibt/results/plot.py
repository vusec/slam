#!/bin/python3
import numpy as np
import matplotlib.pyplot as plt

MAX_NR_LOADS = 10
PLOT_NR_LOADS = 5
rates = [[] for i in range(MAX_NR_LOADS)]

with open("signal.out", "r") as f:
	for line in f:
		words = line.split()
		if len(words) > 1 and words[1] == "experiment":
			length = int(words[8][:-1])
			index = length - 1
			correct = float(f.readline().split()[6][:-1])
			incorrect = float(f.readline().split()[6][:-1])
			mistrained = float(f.readline().split()[5][:-1])
			if correct < 0.2:
				rates[index].append(mistrained)
			else:
				print(f"noisy measurement: {correct} / {incorrect} / {mistrained}")

for i in range(MAX_NR_LOADS):
	print(f"{i+1:2}: {np.average(rates[i]):6.2f}% (+/-{np.std(rates[i]):6.2f})")

avgs = [np.average(rates[i]) for i in range(PLOT_NR_LOADS)]
stds = [np.std(rates[i]) for i in range(PLOT_NR_LOADS)]


# Build the plot
plt.rcParams["figure.figsize"] = (6, 2.5)
fig, ax = plt.subplots()
ax.bar(range(PLOT_NR_LOADS), avgs, yerr=stds, align='center', alpha=0.5, ecolor='black', capsize=10)
ax.set_xlabel('Number of Dependent Loads')
ax.set_ylabel('Successful Leakage Rate')
ax.set_xticks(range(PLOT_NR_LOADS))
ax.set_xticklabels(range(1,PLOT_NR_LOADS+1))
ax.yaxis.grid(True)
ax.set_yticklabels([str(int(t))+"%" for t in ax.get_yticks()])

plt.savefig('fineibt.pdf', format="pdf", bbox_inches="tight")
print("plot saved to fineibt.pdf")
