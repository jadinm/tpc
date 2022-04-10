# Transport Path Changer (TPC) emulation and evaluation

This repository compiles:
- a local deamon, [sr-localctrl](localctrl) exchanging SRv6 paths to the [SRN](https://github.com/segment-routing/srn) controller (loaded as a submodule)
- [scripts](test) to emulate quickly a network with hosts and applications using TPC based on [IPMininet](https://github.com/cnp3/ipmininet) and [SRNMininet](https://github.com/segment-routing/srnmininet)
- [scripts](test) to evaluate the performance of TPC eBPF programs

This repository assumes that you are familiar with eBPF.
If you are not,
[Cilium's documentation](https://docs.cilium.io/en/stable/bpf)
is a good starting point.

## Getting Started

First, be sure that you clone this repository with its submodule.
Install the [SRN in submodule](srn-dev).

Compile the repository's daemon by running the following command
at the root of the repository:

```shell
$ make
```

These programs relies on kernel modifications available
in this [repository](https://github.com/jadinm/tpc-kernel).
You need to have a machine with this kernel to use them.

You also have to compile `bpftool` which will be used to load our
programs and `libbpf` which will generate
the `ebpf_helpers.h` included in most of the eBPF programs.
`bpftool` directory needs to be listed in `PATH` environment variable.

Then, you need to download an compile
[TPC eBPF programs](https://github.com/jadinm/tpc-ebpf).
Define the variable `TPC_EBPF` as the location directory.

Next, you need to install IPMininet and its daemons separately.
The procedure is detailed in their
[installation guide](https://ipmininet.readthedocs.io/en/latest/install.html).

Install
[SRNMininet](https://github.com/segment-routing/srnmininet).

## Emulate a network with TPC

Use the script [run.py](test/run.py) to emulate a simple topology
with exp3-lowest-delay eBPF program.

This script also have other options that can be used to run
evaluations of performance of the other
[eBPF programs of TPC](https://github.com/jadinm/tpc-ebpf).
Run the script with `--help` option to list them.
