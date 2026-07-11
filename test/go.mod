module github.com/powerman/ebpf-same-cgroup-mark/test

go 1.26

require (
	github.com/alecthomas/kong v1.15.0
	github.com/powerman/check v1.13.0
	github.com/powerman/ebpf-same-cgroup-mark v0.0.0
	go.uber.org/mock v0.6.0
)

replace github.com/powerman/ebpf-same-cgroup-mark => ../
