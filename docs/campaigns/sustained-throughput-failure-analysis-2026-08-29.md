# Sustained throughput failure analysis

## Result and evidence preservation

The completed sustained operating-envelope qualification remains an immutable,
valid failed qualification. It is not incomplete and is not eligible for
Conformance credit.

| Property | Value |
| --- | --- |
| Qualification root | `/root/regex-conformance-qualification/sustained-envelope-89ec596b` |
| Source revision | `0ddc106cffad3cf48dd5286bd0f7f204c88c9911` |
| Checkpoints | 54 |
| Final report status | `failed` |
| Failed criterion | `throughput-stability` only |
| Governed degradation | 2,500 basis points (25%) |
| Maximum permitted | 2,000 basis points (20%) |
| Workload digest | `9b5c275b025a4e397c96a2b632ba731555028e4e2f2bb10f7c8f7519f81d5095` |
| Report file SHA-256 | `ed0cc109530194cb5fe4d1e55ca4e84413370474b8e4ed90a9caae32d1853e0a` |
| Preservation manifest | `/root/regex-conformance-qualification/preservation-manifests/sustained-envelope-89ec596b.failed-20260829.sha256` |
| Preservation manifest entries | 1,392 |
| Preservation manifest SHA-256 | `10a7804a848821079c68ff9420483f381942c8a8c7d280a81b302176b96044b7` |

The preservation manifest was created outside the qualification root with
no-overwrite semantics before diagnostic experiments began. All experiments use
the separate root
`/root/regex-conformance-qualification/throughput-diagnostics-20260829`.

The repository compiler reproduced `operating-envelope-report.json`
byte-for-byte. The complete read-only reconstruction is retained outside Git at
`results/failed-run-analysis.json` beneath the diagnostic root. It has SHA-256
`6e0fea7f277161b543da4ba00ba87a4b058057c1101e728dbaf924c2ac02de70`.
That artifact contains, for every stability window, the derived start time,
checkpoint end time, work count, duration, exact and reported throughput,
rolling six-window median, attempt/session state, and every recorded resource
measurement summary.

System-wide available memory and swap were not checkpoint fields in this
qualification. They were observed by the separate hourly health procedure but
cannot be reconstructed per window from the immutable checkpoint chain. The
chain does retain process-group RSS. Processor temperature was explicitly
`unavailable` from the Linux guest in every window. These absences are not
silently replaced with invented values.

## Metric audit

The implemented calculation is deterministic and was independently reproduced:

1. each stability-window rate is rounded upward to an integer
   milli-count/second;
2. the lower median of the 48 rounded values is `4`;
3. the minimum rounded value is `3`;
4. `(4 - 3) / 4` is 25%, or 2,500 basis points.

The calculation uses complete stability windows only. The two interruption and
two recovery event checkpoints contain no window and are excluded. Logical work
is credited once; physical retries do not add another logical completion. The
producer uses `time.monotonic()` for window and iteration durations. Every
workload invocation is a fresh process running the same bound command against
the same input digest.

The idle baseline records resources but completes no workload, so there is no
baseline throughput sample. The governed reference is the deterministic lower
median of all stability windows. The first prefix that crossed the governed
threshold occurred at checkpoint `000010`, after nine stability windows, when
the rounded lower median became `4` while the initial minimum remained `3`.

Integer-milli quantization did not create a false failure. Removing the display
quantization and comparing the exact rational work/duration rates makes the
spread larger: the exact lower median is 3.430484 milli-count/second, the exact
minimum is 2.024055, and the exact minimum-to-median degradation is 4,100 basis
points (41%). The historical result remains 25% under its bound methodology;
the exact figure is diagnostic evidence, not a relabeling of that report.

## Reconstructed curve

The curve is stepwise and cyclical, not monotonic:

- checkpoints `000002`–`000005` form a cold-start band at 2.204–2.323
  milli-count/second;
- `000006`–`000014` rise to a 3.627–3.855 plateau;
- `000015`–`000025` settle mostly at 3.096–3.552;
- the planned recovery at `000027` produced no subsequent work before the
  unexpected interruption at `000028`;
- the usable recovery at `000029` resumed with checkpoint `000030` at 3.080,
  13.13% below the last pre-interruption window;
- `000036`–`000041` fall into a 2.192–2.772 trough;
- `000042`–`000049` recover without another restart to 3.461–3.552;
- `000050`–`000052` contain another trough, including the run minimum at
  `000052`;
- `000053` recovers partially to 3.013.

The early twelve-window lower median is 3.647853 milli-count/second and the
late twelve-window lower median is 3.462087, a 5.10% late reduction. The
pre-recovery lower median is 3.534253 and the post-recovery lower median is
3.080359. Those aggregates and the within-session recoveries show that the run
did not progressively decay for 48 hours; it moved through distinct host-load
bands.

The compact per-window projection follows. Guest CPU is aggregate Ubuntu guest
CPU, not worker-only CPU. Exact start/end timestamps and complete min/max/last
measurement objects remain in the digest-bound external JSON.

| Window / checkpoint | Phase / session | Exact milli-count/s | Rolling 6 median | Work | Duration ms | Guest CPU last / max | RSS max GiB | Disk free min GiB | Cache MiB | Scratch B | Spool KiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 / 2 | steady-load / 1 | 2.216 | — | 8 | 3609327 | 2.99% / 5.26% | 2.697 | 918.345 | 1.570 | 0 | 20 |
| 2 / 3 | steady-load / 1 | 2.204 | — | 8 | 3629872 | 3.11% / 4.76% | 2.684 | 918.345 | 1.570 | 0 | 24 |
| 3 / 4 | steady-load / 1 | 2.288 | — | 9 | 3932869 | 3.08% / 5.55% | 2.697 | 918.345 | 1.570 | 0 | 28 |
| 4 / 5 | steady-load / 1 | 2.323 | — | 9 | 3873469 | 3.16% / 5.55% | 2.684 | 918.345 | 1.570 | 0 | 32 |
| 5 / 6 | steady-load / 1 | 3.627 | — | 14 | 3859885 | 3.13% / 3.33% | 2.683 | 918.345 | 1.570 | 0 | 36 |
| 6 / 7 | steady-load / 1 | 3.670 | 2.288 | 14 | 3814477 | 7.77% / 7.77% | 2.607 | 917.584 | 1.570 | 0 | 40 |
| 7 / 8 | steady-load / 1 | 3.680 | 2.323 | 14 | 3804379 | 3.13% / 15.00% | 2.595 | 917.444 | 1.570 | 0 | 44 |
| 8 / 9 | steady-load / 1 | 3.648 | 3.627 | 14 | 3837875 | 3.09% / 8.33% | 2.588 | 917.444 | 1.570 | 0 | 48 |
| 9 / 10 | steady-load / 1 | 3.761 | 3.648 | 14 | 3722410 | 3.14% / 7.14% | 2.597 | 917.444 | 1.570 | 0 | 52 |
| 10 / 11 | steady-load / 1 | 3.710 | 3.670 | 14 | 3773336 | 3.09% / 7.14% | 2.670 | 917.443 | 1.570 | 0 | 56 |
| 11 / 12 | steady-load / 1 | 3.729 | 3.680 | 14 | 3754694 | 3.10% / 8.15% | 2.669 | 917.443 | 1.570 | 0 | 60 |
| 12 / 13 | steady-load / 1 | 3.810 | 3.710 | 14 | 3674480 | 3.12% / 21.42% | 2.680 | 917.443 | 1.570 | 0 | 64 |
| 13 / 14 | steady-load / 1 | 3.855 | 3.729 | 14 | 3631232 | 3.14% / 3.33% | 2.687 | 917.443 | 1.570 | 0 | 68 |
| 14 / 15 | steady-load / 1 | 3.499 | 3.729 | 13 | 3715582 | 3.14% / 12.50% | 2.549 | 917.443 | 1.570 | 0 | 72 |
| 15 / 16 | steady-load / 1 | 3.096 | 3.710 | 12 | 3876378 | 4.52% / 10.52% | 2.700 | 917.068 | 1.570 | 0 | 76 |
| 16 / 17 | steady-load / 1 | 3.369 | 3.499 | 13 | 3858703 | 3.15% / 7.14% | 2.660 | 917.410 | 1.570 | 0 | 80 |
| 17 / 18 | steady-load / 1 | 3.430 | 3.430 | 13 | 3789553 | 3.15% / 7.69% | 2.537 | 917.410 | 1.570 | 0 | 84 |
| 18 / 19 | steady-load / 1 | 3.496 | 3.430 | 13 | 3718127 | 3.16% / 7.69% | 2.545 | 917.410 | 1.570 | 0 | 88 |
| 19 / 20 | steady-load / 1 | 3.534 | 3.430 | 13 | 3678288 | 3.15% / 6.25% | 2.550 | 917.410 | 1.570 | 0 | 92 |
| 20 / 21 | steady-load / 1 | 3.552 | 3.430 | 13 | 3660062 | 3.15% / 7.14% | 2.554 | 917.410 | 1.570 | 0 | 96 |
| 21 / 22 | steady-load / 1 | 3.525 | 3.496 | 13 | 3687435 | 3.15% / 6.66% | 2.664 | 917.410 | 1.570 | 0 | 100 |
| 22 / 23 | steady-load / 1 | 3.541 | 3.525 | 13 | 3671773 | 3.14% / 12.50% | 2.671 | 917.410 | 1.570 | 0 | 104 |
| 23 / 24 | steady-load / 1 | 3.418 | 3.525 | 13 | 3803325 | 3.17% / 13.33% | 2.715 | 917.410 | 1.570 | 0 | 108 |
| 24 / 25 | steady-load / 1 | 3.546 | 3.534 | 13 | 3666190 | 3.14% / 7.14% | 2.569 | 917.410 | 1.570 | 0 | 112 |
| 25 / 30 | post-recovery / 3 | 3.080 | 3.525 | 12 | 3895651 | 3.76% / 27.27% | 2.675 | 908.607 | 1.570 | 0 | 132 |
| 26 / 31 | post-recovery / 3 | 3.042 | 3.418 | 11 | 3616463 | 3.99% / 12.50% | 2.626 | 908.604 | 1.570 | 0 | 136 |
| 27 / 32 | post-recovery / 3 | 3.175 | 3.175 | 12 | 3779385 | 4.15% / 20.00% | 2.683 | 906.357 | 1.570 | 0 | 140 |
| 28 / 33 | post-recovery / 3 | 2.943 | 3.080 | 11 | 3737788 | 3.22% / 32.00% | 2.690 | 893.259 | 1.570 | 0 | 144 |
| 29 / 34 | post-recovery / 3 | 3.223 | 3.080 | 12 | 3723738 | 3.05% / 25.47% | 2.685 | 889.062 | 1.570 | 0 | 148 |
| 30 / 35 | post-recovery / 3 | 3.097 | 3.080 | 12 | 3874921 | 2.96% / 3.32% | 2.672 | 889.062 | 1.570 | 0 | 152 |
| 31 / 36 | post-recovery / 3 | 2.208 | 3.042 | 9 | 4076628 | 3.08% / 15.65% | 2.681 | 904.461 | 1.570 | 0 | 156 |
| 32 / 37 | post-recovery / 3 | 2.192 | 2.943 | 8 | 3650116 | 3.75% / 34.46% | 2.694 | 889.421 | 1.570 | 0 | 160 |
| 33 / 38 | post-recovery / 3 | 2.219 | 2.219 | 8 | 3604624 | 2.59% / 24.00% | 2.711 | 887.566 | 1.570 | 0 | 164 |
| 34 / 39 | post-recovery / 3 | 2.199 | 2.208 | 8 | 3637739 | 7.16% / 37.12% | 2.705 | 886.941 | 1.570 | 0 | 168 |
| 35 / 40 | post-recovery / 3 | 2.321 | 2.208 | 9 | 3878060 | 8.32% / 31.34% | 2.694 | 886.930 | 1.570 | 0 | 172 |
| 36 / 41 | post-recovery / 3 | 2.772 | 2.208 | 10 | 3607762 | 3.11% / 25.80% | 2.645 | 886.977 | 1.570 | 0 | 176 |
| 37 / 42 | post-recovery / 3 | 3.481 | 2.219 | 13 | 3734784 | 3.11% / 11.11% | 2.540 | 908.579 | 1.570 | 0 | 180 |
| 38 / 43 | post-recovery / 3 | 3.480 | 2.321 | 13 | 3735730 | 3.11% / 3.13% | 2.544 | 908.579 | 1.570 | 0 | 184 |
| 39 / 44 | post-recovery / 3 | 3.461 | 2.772 | 13 | 3755791 | 3.10% / 9.09% | 2.548 | 908.579 | 1.570 | 0 | 188 |
| 40 / 45 | post-recovery / 3 | 3.520 | 3.461 | 13 | 3692906 | 3.10% / 10.00% | 2.551 | 908.579 | 1.570 | 0 | 192 |
| 41 / 46 | post-recovery / 3 | 3.510 | 3.480 | 13 | 3704201 | 3.11% / 11.11% | 2.618 | 908.579 | 1.570 | 0 | 196 |
| 42 / 47 | post-recovery / 3 | 3.552 | 3.481 | 13 | 3660414 | 3.09% / 11.11% | 2.557 | 908.588 | 1.570 | 0 | 200 |
| 43 / 48 | post-recovery / 3 | 3.519 | 3.510 | 13 | 3694492 | 3.10% / 11.11% | 2.614 | 908.588 | 1.570 | 0 | 204 |
| 44 / 49 | post-recovery / 3 | 3.462 | 3.510 | 13 | 3754961 | 3.73% / 36.33% | 2.553 | 897.919 | 1.570 | 0 | 208 |
| 45 / 50 | post-recovery / 3 | 3.292 | 3.510 | 12 | 3644699 | 7.44% / 24.61% | 2.681 | 889.419 | 1.570 | 0 | 212 |
| 46 / 51 | post-recovery / 3 | 2.333 | 3.462 | 9 | 3858364 | 9.35% / 30.43% | 2.685 | 887.093 | 1.570 | 0 | 216 |
| 47 / 52 | post-recovery / 3 | 2.024 | 3.292 | 8 | 3952462 | 12.93% / 28.93% | 2.687 | 887.284 | 1.570 | 0 | 220 |
| 48 / 53 | post-recovery / 3 | 3.013 | 3.013 | 11 | 3650846 | 3.12% / 22.27% | 2.618 | 889.575 | 1.570 | 0 | 224 |

## Causal attribution

### Primary cause: environmental execution topology and contention

The strongest supported cause is the combination of Windows-mounted input
access and intermittent guest/host contention.

- Historical exact throughput correlates negatively with aggregate guest CPU
  `last` (-0.403) and `maximum` (-0.450), and positively with minimum free disk
  (+0.533). These are diagnostic correlations, not proofs of independent
  causation.
- Windows-limited slow windows averaged 5.41% guest CPU at the last sample and
  a 20.28% window maximum, compared with 3.33% and 10.09% for windows at or
  above the exact median.
- Slow windows averaged about 13.9 GiB less free guest-root space than fast
  windows. The large within-window free-space swings cannot be produced by the
  fixed 1.57 MiB Evidence Pack output or 4 KiB/checkpoint spool growth.
- The useful WSL/process recovery did not restore peak throughput immediately:
  its first window was 13.13% below the last pre-interruption window. The same
  session later recovered to 3.5 milli-count/second without another restart.
  This rejects a simple persistent Python-process leak and favors changing host
  load or filesystem conditions.

A bounded M–N–M–N experiment compared the original `/mnt/c` source with a
byte-identical native-WSL copy. The two source trees had the same 36,643,494-byte
size and the same aggregate file digest
`e9294da86a09ebb89e0f4e13715e11616e56933ff185279537335ffd910edaa9`.

| Input | Run 1 elapsed | Run 2 elapsed | Mean | Mean process CPU | Voluntary context switches |
| --- | ---: | ---: | ---: | ---: | ---: |
| `/mnt/c` | 301.00 s | 313.28 s | 307.14 s | 85% | 244,750 / 253,186 |
| Native WSL | 267.42 s | 270.95 s | 269.19 s | 97% | 23,174 / 24,829 |

User CPU was essentially the same in both cases. Native staging reduced mean
elapsed time by 12.36%, increased worker CPU occupancy, and removed roughly 90%
of the voluntary-switch wait signature. Both output trees were exactly
1,376,122 bytes with the same aggregate digest
`42c1a34b38f2424ee71b890796d042c397b8a7ad408ced1e2aa4aa03d4487b8c`.

### Contributing cause: cold and changing host state

The first four stability windows are 36–43% slower than the first fast plateau.
They establish an early minimum before caches and host state settle. This is a
real operating-envelope observation and is not removed from the failed report.
It is not the final cause by itself because checkpoint `000052` later produced
an even lower exact rate.

Windows event history contained no Kernel-Processor-Power throttling event and
no resource-exhaustion event during the run. Defender scan times do not align
with the long slow bands, and Docker logs stop before the resumed workload.
The active power plan observed after completion was Balanced, but no historical
frequency or package-temperature series was retained. Thermal throttling is
therefore unsupported by affirmative evidence, not proven impossible.

### Rejected primary causes

- **Growing Python state:** every transcode is a fresh process.
- **Allocator or RSS growth:** per-window maximum RSS stays approximately
  2.54–2.72 GiB, and bounded experiments stay near 2.72 GiB.
- **Output/cache accumulation:** environment cache remains 1.57 MiB, scratch is
  zero, spool grows exactly 4 KiB per checkpoint, and repeated output trees are
  byte-identical.
- **Super-linear repeated work:** fixed user-plus-system CPU time remains stable
  across fresh processes; only wall/CPU occupancy changes materially.
- **Metric false positive:** independent arithmetic reproduces 25%; exact
  rational rates show a larger, not smaller, spread.

## Ranked causal assessment

| Hypothesis | Supporting evidence | Evidence against | Confidence | Contribution | Correctable / risk |
| --- | --- | --- | --- | --- | --- |
| `/mnt/c` filesystem waits | 12.36% A/B gain; equal CPU work; 10× context-switch reduction | Does not explain the entire historical trough | High | About 12% mean elapsed time in the bounded comparison | Yes; low risk because bytes and outputs are digest-identical |
| Intermittent guest/host contention | Negative CPU correlation, free-space swings, high-CPU slow bands, recovery without restart | Historical per-process scheduler trace is unavailable | High | Residual and episodic; overlaps filesystem waits and cannot be added linearly | Yes through host-isolation preflight; operational risk if unrelated work starts later |
| Cold cache/host warm-up | First four windows form a distinct low band | Later minimum is lower | Medium | Material to the early minimum, not sufficient for the final failure | Partly; native staging reduces the cross-filesystem component |
| Thermal or power limiting | Long-running host makes it plausible | No throttle events; no temperature/frequency series; curve recovers without restart | Low | Unquantified | Not justified without new telemetry |
| Evidence Pack scaling defect | High absolute CPU cost | Fresh processes, fixed CPU work, flat RSS/output, no monotonic trend | Low | No supported repeated-run contribution | No code optimization justified by this failure |
| Defender or Docker interference | Both can contend for host resources | Recorded times do not align with troughs | Low | No supported direct contribution | No remediation justified |

## Remediation and short-run validation

The minimum justified remediation is operational:

1. stage the immutable Evidence Pack v2 input on native WSL ext4;
2. verify the staged tree digest and byte count against the source;
3. bind both the new qualification and workload command to the native path;
4. retain cache, scratch, spool, and checkpoints on native WSL storage;
5. require a host-isolation preflight showing no unrelated sustained WSL
   workload and safe guest/host resources;
6. keep the 20% threshold and all evidence semantics unchanged;
7. use a new qualification identity/root and preserve the failed run.

Ten native fresh-process samples, including eight continuous retained-output
runs, completed in 240.63–270.95 seconds. Their exact minimum-rate to lower-
median-rate degradation is 222 basis points (2.22%). The late-five median is
1.02% faster than the early-five median. Peak RSS and output size remain flat,
and every output has the expected deterministic digest.

The short regression predicts sustained degradation below 10% under the same
native-input and host-isolation conditions. That prediction is deliberately
wider than the observed 2.22% because the failed run contained multi-hour host
cycles that a short test cannot sample. A medium-duration rehearsal is still
required before starting the independent 48-hour replacement qualification.

```text
SUSTAINED THROUGHPUT FAILURE ANALYSIS

Original qualification: FAILED
Checkpoints: 54
Threshold: 20%
Observed degradation: 25%

Independent metric reproduction: PASS

Primary cause:
Environmental execution topology: Windows-mounted input waits compounded by
intermittent guest/host contention.

Contributing causes:
Cold/changing host state established early low windows; integer-milli
quantization under-reported the exact spread but did not cause a false failure.

Evidence:
Exact raw spread 41%; mounted/native A/B improvement 12.36%; native short-run
degradation 2.22%; flat RSS/cache/scratch/output; identical Evidence Pack bytes;
negative throughput/guest-CPU correlation and large unrelated free-space swings.

Remediation:
Stage and digest-verify immutable input on native WSL storage, bind execution to
that path, and require a host-isolation preflight. Preserve the 20% limit.

Short-run validation:
PASS — 10 native fresh-process samples, 240.63–270.95 seconds, 2.22% exact
minimum-to-lower-median rate degradation, no late decline, identical output.

Predicted sustained degradation after remediation:
Below 10% under the validated native-input and host-isolation conditions.

Ready for replacement 48-hour qualification: NO
Reason: medium-duration sustained rehearsal has not yet passed.
```
