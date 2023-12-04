LAM/UAI Switching
=================

To reproduce our evaluation of the mitigation that switches LAM/UAI off/on upon
kernel entry/exit (Table 4 of the paper), do the following.

We assume you are running an Ubuntu 22.04 installation on an Intel or AMD
machine.

Baseline Kernel
---------------

Download the Linux kernel 6.3 source code.
```
wget https://github.com/torvalds/linux/archive/refs/tags/v6.3.zip
unzip v6.3.zip
rm v6.3.zip
cd linux-6.3
```

Configure the kernel as we did (Ubuntu defaults). On Intel that is
```
cp ../switch-lam.config .config
```
On AMD that is
```
cp ../switch-uai.config .config
```

Build the kernel as a Debian package.
```
make -j`nproc` bindeb-pkg
```

Switching Kernel
----------------

Apply the switching patch. On Intel machines that is
```
git apply ../switch-lam.patch
```
while on AMD machines that is
```
git apply ../switch-uai.patch
```

Set the kernel's name.
```
sed -i 's/\(CONFIG_LOCALVERSION="\)/\1-switch/g' .config
```

Build this kernel as well.
```
make -j`nproc` bindeb-pkg
```

Install Kernels
---------------

Now install both kernels.
```
dpkg -i ../linux-*.deb
```

Reboot into the kernel you want to benchmark first.
```
grub-reboot [kernel-number]
reboot
```

LMBench
-------

Download the LMBench source code.
```
git clone https://github.com/intel/lmbench.git
```

Fix this broken version of LMBench on Ubuntu.
```
git apply ../lmbench-ubuntu.patch
```

Configure, build, and run LMBench. We configured using the defaults, except for
setting the memory to use to 512MB, cf. `lmbench-*.config` for our config files.
```
make results
```

To run multiple rounds, use
```
make rerun
```

Next, switch to the other kernel (baseline vs switching) and repeat.

Results
-------
You can find our results in the [results](results) folder. The `*.out` files
contain the raw output of our LMBench runs. The `summarize.py` script dumps
Table 4 of the paper (Latex formatted) together with geomeans.
