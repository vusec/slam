#!/bin/python3

import sqlite3
import pandas as pd
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import StrMethodFormatter

parser = argparse.ArgumentParser(description='Analyze Unmasked Gadget Scanning Results')
parser.add_argument('-s', '--show', action="store_true")
args = parser.parse_args()

db = sqlite3.connect("gadgets.db")

def query(query_filename):
	with open(f"./queries/{query_filename}.sql", "r") as f:
		q = f.read()
	return pd.read_sql_query(q, db)

def save(save_filename):
	filename = f'figures/{save_filename}.pdf'
	plt.savefig(filename, format="pdf", bbox_inches="tight")
	print(f"Saved to {filename}")

def hist_plot(df, column, bins, xlabel, ylabel, add_numbers):
	ax = df.hist(column=column, bins=bins, grid=False, figsize=(12,8), color='#86bf91', zorder=2, rwidth=0.9)
	ax = ax[0][0]
	ax.spines['right'].set_visible(False)
	ax.spines['top'].set_visible(False)
	ax.set_xlim(0)
	vals = ax.get_yticks()
	for tick in vals:
		ax.axhline(y=tick, linestyle='dashed', alpha=0.4, color='#eeeeee', zorder=1)
	ax.set_title("")
	ax.set_xlabel(xlabel, size=12)
	ax.set_ylabel(ylabel, size=12)
	ax.yaxis.set_major_formatter(StrMethodFormatter('{x:,g}'))
	if add_numbers:
		for rect in ax.patches:
			height = rect.get_height()
			ax.annotate(f'{int(height)}', xy=(rect.get_x()+rect.get_width()/2, height), 
						xytext=(0, 0), textcoords='offset points', ha='center', va='bottom') 

	if args.show:
		plt.show()
	else:
		save(column)

def put_text(ax, x, y):
	x_diff = 0.1 * len(str(int(y)))
	ax.text(x-x_diff, y+30, str(int(y)))


print("SLAM's Unmasked Gadget Database looks like this:\n")
print(pd.read_sql_query("SELECT * FROM translations", db))

print("\n___________________________________________________________________\n")

nr_gadgets = query("all/count_gadgets").iat[0,0]
nr_translations = query("all/count_translations").iat[0,0]
nr_leakage_paths = query("all/count_all").iat[0,0]
nr_simple_gadgets = query("simple/count_gadgets").iat[0,0]
nr_simple_translations = query("simple/count_translations").iat[0,0]
nr_simple_leakage_paths = query("simple/count_all").iat[0,0]
print(f"Number of unmasked gadgets (simple / all): {nr_simple_gadgets:7} / {nr_gadgets:7}")
print(f"Number of translations (simple / all):     {nr_simple_translations:7} / {nr_translations:7}")
print(f"Number of leakage paths (simple / all):    {nr_simple_leakage_paths:7} / {nr_leakage_paths:7}")

print("\n___________________________________________________________________\n")

df = query("all/load_vs_store")
nr_load_gadgets = df.iat[0,1]
nr_store_gadgets = df.iat[1,1]
nr_load_store_gadgets = nr_load_gadgets + nr_store_gadgets - nr_gadgets
nr_only_load_gadgets = nr_load_gadgets - nr_load_store_gadgets
nr_only_store_gadgets = nr_store_gadgets - nr_load_store_gadgets
df = query("simple/load_vs_store")
nr_simple_load_gadgets = df.iat[0,1]
nr_simple_store_gadgets = df.iat[1,1]
nr_simple_load_store_gadgets = nr_simple_load_gadgets + nr_simple_store_gadgets - nr_simple_gadgets
nr_simple_only_load_gadgets = nr_simple_load_gadgets - nr_simple_load_store_gadgets
nr_simple_only_store_gadgets = nr_simple_store_gadgets - nr_simple_load_store_gadgets
print(f"Number of only load gadgets (simple / all):           {nr_simple_only_load_gadgets:7} / {nr_only_load_gadgets:7}")
print(f"Number of only store gadgets (simple / all):          {nr_simple_only_store_gadgets:7} / {nr_only_store_gadgets:7}")
print(f"Number of both load and store gadgets (simple / all): {nr_simple_load_store_gadgets:7} / {nr_load_store_gadgets:7}")


################################################################################
################################################################################


print("\n___________________________________________________________________\n")

df = query("all/min_insts_hist")
df["simple"] = query("simple/min_insts_hist")["simple"]
df = df.reindex(columns=["min_insts", "simple", "total"])
df = df.set_index("min_insts")
print(df)

plt.rcParams["figure.figsize"] = (8, 4)
fig, ax = plt.subplots()
df = query("all/min_insts").rename(columns={"min_insts": "Instructions (Total)"})
df.hist(cumulative=1, histtype='step', bins=[0.5+i for i in range(41)] + [np.inf], ax=ax, color="blue", legend=True)
df = query("simple/min_insts").rename(columns={"min_insts": "Instructions (Simple)"})
df.hist(cumulative=1, histtype='step', bins=[0.5+i for i in range(41)] + [np.inf], ax=ax, color="blue", legend=True, linestyle="dashed")
ax.set_xlim((ax.get_xlim()[0], 40))
ax.legend(loc="lower right")
ax.set_ylabel("Number of Unmasked Gadgets")
ax.set_xlabel("Number of Instructions")
ax.set_title("")
plt.grid(axis='x')
for tick in ax.get_xticks():
	ax.axvline(x=tick, linestyle='dashed', alpha=0.4, color='#cccccc', zorder=1)
ax = ax.twiny()
df = query("all/min_bbs").rename(columns={"min_bbs": "Basic Blocks (Total)"})
df.hist(cumulative=1, histtype='step', bins=[0.5+i for i in range(24)] + [np.inf], ax=ax, color="orange", legend=True)
df = query("simple/min_bbs").rename(columns={"min_bbs": "Basic Blocks (Simple)"})
df.hist(cumulative=1, histtype='step', bins=[0.5+i for i in range(24)] + [np.inf], ax=ax, color="orange", legend=True, linestyle="dashed")
ax.set_xlim((ax.get_xlim()[0], 23))
ax.legend(loc="center right")
ax.set_xlabel("Number of Basic Blocks")
ax.set_title("")
plt.grid(axis='x')
for tick in ax.get_xticks():
	ax.axvline(x=tick, linestyle='dashed', alpha=0.4, color='#cccccc', zorder=1)
plt.savefig("figures/cdf.pdf", format="pdf", bbox_inches="tight")
plt.show()


################################################################################
################################################################################



print("\n___________________________________________________________________\n")

# Print exact numbers to command line.
print("Minimal number of basic blocks to reach the first secret translation per gadget.")
df = query("not-simple/min_bbs_hist")
df["simple"] = query("simple/min_bbs_hist")["simple"]
df = df.reindex(columns=["min_bbs", "simple", "not_simple"])
print(df)
ax = df.plot.bar(x='min_bbs', stacked=True, grid=False, figsize=(12,8), color=['#4a8ed5', '#86bf91'], zorder=2, width=0.8)
xlabel = "Minimal Number of Basic Blocks to Reach Secret Translation"
ylabel = "Number of Unmasked Gadgets"
ax = ax
ax.spines['right'].set_visible(False)
ax.spines['top'].set_visible(False)
# ax.set_xlim(-1)
# ax.set_ylim((0, 1400))
vals = ax.get_yticks()
for tick in vals:
	ax.axhline(y=tick, linestyle='dashed', alpha=0.4, color='#eeeeee', zorder=1)
ax.set_title("")
ax.set_xlabel(xlabel, size=12)
ax.set_ylabel(ylabel, size=12)
ax.yaxis.set_major_formatter(StrMethodFormatter('{x:,g}'))
put_text(ax, 0, df["simple"][0])
put_text(ax, 0, df["simple"][0]+df["not_simple"][0])
for i in range(1, len(df["not_simple"])):
	put_text(ax, i, df["not_simple"][i])
ax.legend(loc='upper right')
if args.show:
	plt.show()
else:
	save("nr_bbs")


print("\n___________________________________________________________________\n")

print("Which registers should an attacker control?")
print(query("simple/registers_indirect"))
print(query("simple/registers"))
df = query("all/registers")
print(df)
regs = [row['attacker_registers'].replace("', '", "+")[2:-2] for i, row in df.iterrows()]
total = [row['total'] for i, row in df.iterrows()]
df = pd.DataFrame(data=total, index=regs)
print(df)
xlabel = "Number of Unmasked Gadgets"
ylabel = "Registers Requiring Attacker Control"
ax = df.plot.barh(grid=False, figsize=(12,8), color='#86bf91', zorder=2, legend=False)
ax.spines['right'].set_visible(False)
ax.spines['top'].set_visible(False)
ax.set_xlim(0)
vals = ax.get_xticks()
for tick in vals:
	ax.axvline(x=tick, linestyle='dashed', alpha=0.4, color='#eeeeee', zorder=1)
ax.set_title("")
ax.set_xlabel(xlabel, size=12)
ax.set_ylabel(ylabel, size=12)
for i, v in enumerate(total):
    ax.text(v + 10, i - 0.1, str(v))
if args.show:
	plt.show()
else:
	save("registers")


db.close()
