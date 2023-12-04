Covert Channel Intel
====================

Reproduce our covert channel experiment on the Ryzen 7 2700X as follows.

Ensure the `kslam` kernel module is inserted, cf. [kernel](../../../kernel).

Build it.
```
make
```

Then run it, as root.
```
./covert
```

Note that you can change the verbosity of the output via the
[slam.h](../lib/slam.h) constant `VERBOSITY`.

You can find output, together with a summarizing script, in [results](results).
