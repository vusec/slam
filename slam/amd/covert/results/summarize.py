#!/bin/python3

import numpy as np

for filename in ["uai_on.out", "uai_off.out"]:
        rates = []
        accur = []
        rewinds = []
        f = open(filename, "r")
        for line in f:
                words = line.split()
                if words[0] == "Leakage":
                        rates.append(float(words[2]))
                if words[0] == "Accuracy:":
                        accur.append(float(words[4][1:-2]))
                if words[0] == "Number":
                        rewinds.append(float(words[3]))
        f.close()
        
        print(f"{filename}: leakage rate {np.average(rates)} (+/-{np.std(rates)})")
        print(f"{filename}: accuracy {np.average(accur)} (+/-{np.std(accur)})")
        print(f"{filename}: rewinds {np.average(rewinds)} (+/-{np.std(rewinds)})")

