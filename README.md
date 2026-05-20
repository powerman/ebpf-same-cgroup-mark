# ebpf-same-cgroup-mark

[![License MIT](https://img.shields.io/badge/license-MIT-royalblue.svg)](LICENSE-MIT)
[![License GPL-2.0](https://img.shields.io/badge/license-GPL--2.0-royalblue.svg)](LICENSE-GPL-2.0)
[![Test](https://img.shields.io/github/actions/workflow/status/powerman/ebpf-same-cgroup-mark/test.yml?label=test)](https://github.com/powerman/ebpf-same-cgroup-mark/actions/workflows/test.yml)
[![Coverage Status](https://raw.githubusercontent.com/powerman/ebpf-same-cgroup-mark/gh-badges/coverage.svg)](https://github.com/powerman/ebpf-same-cgroup-mark/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/powerman/ebpf-same-cgroup-mark)](https://goreportcard.com/report/github.com/powerman/ebpf-same-cgroup-mark)
[![Release](https://img.shields.io/github/v/release/powerman/ebpf-same-cgroup-mark?color=blue)](https://github.com/powerman/ebpf-same-cgroup-mark/releases/latest)

![Linux | amd64 arm64](https://img.shields.io/badge/Linux-amd64%20arm64-royalblue)

Set `SO_MARK` on a TCP client socket
when the destination listener socket lives in the same cgroup.

## Requirements

- Linux kernel with BPF support (CONFIG_BPF, CONFIG_BPF_SYSCALL).

## Installation

### Binary release

Download a pre-built binary from the
[releases page](https://github.com/powerman/ebpf-same-cgroup-mark/releases/latest),
save in `$PATH` and make executable.

### From source

Build requirements:

- Linux kernel headers (for `bpf/bpf_helpers.h` etc.).
- `clang` (for compiling the BPF program from source).
- [mise](https://mise.jdx.dev/).

```sh
mise run build
```

Produces the `.cache/ebpf-same-cgroup-mark` binary with an embedded BPF object.

## Usage

Load and attach the BPF program (unloads any previous instance first):

```sh
sudo ebpf-same-cgroup-mark load
```

Override the default mark mask (`0x40000000`):

```sh
sudo ebpf-same-cgroup-mark load -m 0x20000000
```

Detach and unload:

```sh
sudo ebpf-same-cgroup-mark unload
```

### Example nftables integration

```nft
define same_cgroup_mark = 0x40000000

socket mark & $same_cgroup_mark == $same_cgroup_mark accept
```

Use the same bit value both in nftables and in the mark config.

## How it works

The implementation uses four cgroup BPF hooks attached at `/sys/fs/cgroup`:

- `cgroup/bind4`
- `cgroup/bind6`
- `cgroup/connect4`
- `cgroup/connect6`

The bind hooks store the creator cgroup ID in socket-local storage
for TCP listener sockets.
The connect hooks look up the destination listener,
compare its stored cgroup ID against the current task's cgroup,
and OR a configurable mark bit into `SO_MARK` when they match.

Because `bpf_sk_lookup_tcp()` only searches the local socket table in the
current network namespace,
this mechanism affects only local listeners on the same machine.
It does not mark ordinary remote TCP connections to external hosts.
