# Gadget scanning

To reproduce our gadget finder results, run our scanner on the Linux Kernel as
follows.

## Input

### Indirect branch targets

We analyzed indirect branch targets in the Linux kernel. To collect the
list of entry points we used an
[LLVM pass](https://github.com/IntelLabs/Branch-Target-Injection-Gadget-Finder)
created by Intel researchers. We output the
function name on each newly found indirect call target.
The resulting list can be found in the input folder.

### Linux kernel

We analyzed the Linux kernel 6.3.0 with default configuration. To build the kernel:

```bash
wget https://github.com/torvalds/linux/archive/refs/tags/v6.3.zip
unzip v6.3.zip
cd linux-6.3

make defconfig
make -j`nproc`
```

## Running the scanner

The scanner can be found in [scanner](scanner). General usage:

```bash
usage: main.py [-h] [-p] [-n GADGET_NAME] -a GADGET_ADDRESS binary_file

SLAM Unmasked Gadget Finder

positional arguments:
  binary_file

options:
  -h, --help            show this help message and exit
  -p, --pickle-project
  -n GADGET_NAME, --gadget-name GADGET_NAME
  -a GADGET_ADDRESS, --gadget-address GADGET_ADDRESS
```

To run the scanner for one entry point (name can be anything):

``` bash
cd scanner
python3 main.py -p -n kernfs_seq_show -a 0xffffffff8130b0f0 ../linux-6.3/vmlinux
```

To scan all targets with a single core:

``` bash
cd scripts
./run_single.sh ../input/indirect-branch-targets_linux-6.3.0.txt ../linux-6.3/vmlinux
```

To scan all targets with multiple cores:

``` bash
cd scripts
./run_multi_core.sh `nproc` output ../input/indirect-branch-targets_linux-6.3.0.txt ../linux-6.3/vmlinux
```

## Output

For each found translation (transmitting a secret), the scanner outputs a log
line. With the script `scripts/log_to_db.py`, you can convert this to a sqlite3
database:

```bash
python3 log_to_db.py raw_log_file.txt gadgets.db
```

## Results

Our results on Linux 6.3 are in the [results](results) folder. The file
`raw_results_linux_v6.3.0.tar.gz` contains the raw output log, and the
corresponding database table is called `translations` in `gadgets.db`. We also
added a table `ibts`, that stores all indirect branch targets reached by a
24 hour fuzzing campaign of syzkaller against the Linux kernel.

To regenerate the paper's Figure 11 and the numbers from Table 2 (and more): 

``` bash
cd results
python3 analyze.py
```
