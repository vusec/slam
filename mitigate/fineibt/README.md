FineIBT
=======

Reproduce our evaluation of the FineIBT mitigation on a Intel machine supporting
IBT as follows.

Ensure that the `kslam` kernel module is installed, cf. [kernel](../../kernel).

Then build and run the FineIBT test:
```
make
./fineibt
```

Our results, together with a script producing Figure 13, are in [results](results).
