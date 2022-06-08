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

Its final output should be similar to the following:
```
== Figure 8 (pmemtrace.py) results ==
                                               count  mean               sstdev
total elapsed tracer process time:             20     6.374              0.11495536891379
->boot (only minimal instrumentation):         20     1.6254023430869    0.02828601624545
->trace (from outside):                        20     4.152885376662     0.098335081859825
->->trace (in guest, portion of command):      20     3.016              0.051646572210096
execution in guest with raw PANDA:             20     0.0895             0.0022360679774998

== Figure 9 (trace2img.py) results ==
                                               count  mean               sstdev
total elapsed process time:                    20     83.8215            0.52551002794779
->boot:                                        20     1.6333558445796    0.033064026122977
->crash image generator:                       20     37.874895266071    0.32519190866099
->->cross-failure tracing (heuristic):         12     1.9969639750198    0.28365390070709
->tester:                                      20     43.645736410469    0.35437410606065
->->reset to snapshot & load image:            31     0.075392498364372  0.0056485017603337
->->run dumper command (PANDA):                31     1.0400925968443    0.11656504327783

The tester processes 31 unique crash images
that stem from 77 origins (§3.3)
and result in 7 unique semantic crash states.

success
```

The tables should approximately reproduce the numbers in Figure 8 and Figure 9 (depending on the hardware used).
The paragraph at the end of the output should further contain the same numbers as the corresponding sentence in §6.3.
