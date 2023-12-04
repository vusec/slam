SLAM: Spectre based on Linear Address Masking
=============================================

This repository contains the code and data of the S&P'24 paper titled

[Leaky Address Masking: Exploiting Unmasked Spectre Gadgets with Noncanonical Address Translation](https://download.vusec.net/papers/slam_sp24.pdf).

For more information about the SLAM attack project, read the paper or visit
[this webpage about SLAM](https://www.vusec.net/projects/slam).

Overview
--------

The contents of this repository are organized as follows:
- [gadget](gadget): unmasked gadget scanner and results
- [kernel](kernel): auxiliary kernel functionality 
- [mitigate/fineibt](mitigate/fineibt) FineIBT mitigation 
- [mitigate/switch](mitigate/switch) LAM/UAI-switching mitigation
- [slam/amd/covert](slam/amd/covert) SLAM covert channel on AMD
- [slam/intel/covert](slam/intel/covert) SLAM covert channel on Intel
- [slam/intel/exploit](slam/intel/exploit) SLAM end-to-end exploit on Intel

Reproduction
------------
To reproduce the results from our paper, follow the instructions in the
corresponding folder(s):
- Covert channel bandwidth and retransmission rates (Table 1):
        [slam/amd/covert](slam/amd/covert) and
        [slam/intel/covert](slam/intel/covert)
- Gadget lengths (Figure 11) and types and controllability (Table 2):
        [gadget](gadget)
- Exploit bandwidth and run times (Table 3) and run time breakdowns (Figure 12):
        [slam/intel/exploit](slam/intel/exploit)
- LAM/UAI-switching mitigation performance (Table 4):
        [mitigate/switch](mitigate/switch)
- FineIBT mitigation evaluation (Figure 13):
        [mitigate/fineibt](mitigate/fineibt)
