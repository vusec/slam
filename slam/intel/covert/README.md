Covert Channel Intel
====================

Reproduce our covert channel experiment on the i9-13900K as follows.

First, make sure you inserted the `kslam` kernel module, cf.
[kernel](../../../kernel).

Then, build it and, as root, run it.
```
make
./covert
```

Note that you can change the verbosity of the output via the `VERBOSITY`
constant in [slam.h](../lib/slam.h).

You can find our output, together with a summarizing script, in
[results](results).
