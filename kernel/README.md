Kernel
======

SLAM comes with two kernel parts: `kslam` and `linux-6.3-lam`.

kslam
-----
The kernel module `kslam` in `kslam.c` provides auxiliary functionality from
the kernel to SLAM. `kslam` exports some procfs files at `/proc/kslam/*`. In
short, it provides:
- `direct_map`: provides the virtual address at which Linux' direct map of
                physical memory starts;
- `fineibt_*`: files used for evaluating the FineIBT mitigation;
- `gadget_*`: "ideal" unmasked Spectre disclosure gadgets.

In particular, `gadget` is a fully unmasked gadget, while `gadget_lam` and
`gadget_uai` respectively provide unmasked gadgets as if Intel LAM or AMD UAI
(respectively) are enabled.

linux-6.3-lam
-------------
SLAM's end-to-end exploit targets Linux 6.3. As, at the time of writing, Intel
LAM is not yet released to production, we emulate LAM in software.
Specifically, we emulate LAM for the specific unmasked gadgets that we examine
in the paper. This emulation is done by patching the Linux 6.3 source code.

To build `linux-6.3-lam`, first get the Linux 6.3 source code.
```
wget https://github.com/torvalds/linux/archive/refs/tags/v6.3.zip
unzip v6.3.zip
rm v6.3.zip
cd linux-6.3
```

Then apply our kernel patch that emulates Intel LAM in software for the gadgets
that we target.
```
git apply ../lam.patch
```

If you want to use the same (default Ubuntu) configuration as we did:
```
cp ../lam.config .config
```

Build, install, and reboot into `linux-6.3-lam`:
```
make -j`nproc` bindeb-pkg
dpkg -i ../linux-*.deb
grub-reboot [kernel-number of linux-6.3-lam]
reboot
```
