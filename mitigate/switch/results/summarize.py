#!/bin/python3

from pprint import pprint
import numpy as np
from scipy.stats import gmean

def parse_file(file):
	data = {}
	with open(file, "r") as f:
		for line in f:
			while not line.startswith("Simple syscall"):
				line = f.readline()
				if len(line) == 0:
					break
			while len(line) > 1:
				benchmark, result = line.split(":")
				value, unit = result.split()
				value = float(value)
				try:
					data[benchmark].append(value)
				except KeyError:
					data[benchmark] = [value]
				line = f.readline()
	return data

intel_baseline = parse_file("intel-baseline.out")
intel_mitigation = parse_file("intel-mitigation.out")
amd_baseline = parse_file("amd-baseline.out")
amd_mitigation = parse_file("amd-mitigation.out")

names = [
	["Simple syscall", "Simple syscall"],
	["Simple read", "Simple read"],
	["Simple write", "Simple write"],
	["Simple stat", "Simple stat"],
	["Simple fstat", "Simple fstat"],
	["Simple open/close", "Simple open/close"],
	["Select on 10 fd's", "Select on 10 fd's"],
	["Select on 100 fd's", "Select on 100 fd's"],
	["Select on 250 fd's", "Select on 250 fd's"],
	["Select on 500 fd's", "Select on 500 fd's"],
	["Select on 10 tcp fd's", "Select on 10 tcp fd's"],
	["Select on 100 tcp fd's", "Select on 100 tcp fd's"],
	["Select on 250 tcp fd's", "Select on 250 tcp fd's"],
	["Select on 500 tcp fd's", "Select on 500 tcp fd's"],
	["Signal handler installation", "Signal handler install"],
	["Signal handler overhead", "Signal handler"],
	["Protection fault", "Protection fault"],
	["Pipe latency", "Pipe latency"],
	["AF_UNIX sock stream latency", "Unix socket stream"],
	["Process fork+exit", "Process fork+exit"],
	["Process fork+execve", "Process fork+execve"],
	["Process fork+/bin/sh -c", "Process fork+/bin/sh"],
	# ["File /var/tmp/XXX write bandwidth", "File /var/tmp/XXX write bandwidth"],
	["Pagefaults on /var/tmp/XXX", "Pagefaults"],
]

intel_overheads = []
amd_overheads = []
for i in range(len(names)):
	benchmark, name = names[i]
	# Intel
	ibas = np.median(intel_baseline[benchmark])
	ibaslen = len(intel_baseline[benchmark])
	imit = np.median(intel_mitigation[benchmark])
	imitlen = len(intel_mitigation[benchmark])
	ioverhead = imit/ibas
	# AMD
	abas = np.median(amd_baseline[benchmark])
	abaslen = len(amd_baseline[benchmark])
	amit = np.median(amd_mitigation[benchmark])
	amitlen = len(amd_mitigation[benchmark])
	aoverhead = amit/abas
	# Accumulate
	intel_overheads.append(ioverhead)
	amd_overheads.append(aoverhead)
	# Formatting
	color = "\\rowcolor{gray!10}" if i % 2 else ""
	ioverhead = f"{ioverhead:.2f}x" if ioverhead >= 200.0 else f"{100*(ioverhead-1):.1f}\\%"
	aoverhead = f"{aoverhead:.2f}x" if aoverhead >= 200.0 else f"{100*(aoverhead-1):.1f}\\%"
	# print(f"{name:30} {ibas:10.4f} ({ibaslen}) vs {imit:10.4f} ({imitlen})   {ioverhead:7}   ---  {abas:10.4f} ({abaslen}) vs {amit:10.4f} ({amitlen})   {aoverhead:7}")
	print(f"{name:23}  & {ibas:10.3f}$\\mu$s  &   {ioverhead:7}  & {abas:10.3f}$\\mu$s  &   {aoverhead:7} \\\\ {color:20}")

print(f"Intel geomean overhead: {gmean(intel_overheads)}x")
print(f"AMD   geomean overhead: {gmean(amd_overheads)}x")
