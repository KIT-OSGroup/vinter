Performance Benchmarks
======================

This walkthrough reproduces the most important results from §6.3 "Performance".
Most importantly, it reproduces Figure 8 and Figure 9.

Execute in a shell from the Vinter root directory:
```
fs-testing/scripts/script_run-paper-benchmark.sh
```

The benchmark may take between 30 and 60 minutes to complete and writes its
files to `results_paper-benchmark`.

Its final output should be similar to the following (only placeholder values listed here):
```
== Figure 8 (pmemtrace.py) results ==
                                               count  mean               sstdev
total elapsed tracer process time:             20     6.04               4.4494718330153e-19
->boot (only minimal instrumentation):         20     1.5320778638124    2.2247359165076e-19
->trace (from outside):                        20     3.8895835317671    0
->->trace (in guest, portion of command):      20     2.36               2.2247359165076e-19
execution in guest with raw PANDA:             20     0.0895             0.015035046776746

== Figure 9 (trace2img.py) results ==
                                               count  mean               sstdev
total elapsed process time:                    20     84.52              7.1191549328245e-18
->boot:                                        20     1.5242083892226    3.3371038747615e-19
->crash image generator:                       20     38.556703411043    0
->->cross-failure tracing (heuristic):         12     2.0293949271242    0.46475635500365
->tester:                                      20     43.777359969914    0
->->reset to snapshot & load image:            31     0.080034287826669  0.0049169874557684
->->run dumper command (PANDA):                31     1.0457796561382    0.094908553471208

The tester processes 31 unique crash images
that stem from 77 origins (§3.3)
and result in 7 unique semantic crash states.

success
```

NOTE: The benchmark results listed in the paper PDF are not yet up to date with the latest artifact version. The differences are not big though.

The tables should approximately reproduce the numbers in Figure 8 and Figure 9 (depending on the hardware used).
The paragraph at the end of the output should further contain the same numbers as the corresponding sentence in §6.3.
