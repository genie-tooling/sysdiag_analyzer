// Package ebpf traces process exec/exit via eBPF and attributes events to units.
//
// The actual loader lives in tracer.go behind the `ebpf` build tag and depends
// on a CO-RE object compiled from bpf/tracer.c. Generating it needs clang +
// bpftool (build-time only; the runtime needs only a BTF-capable kernel):
//
//	go generate ./...                 # produces vmlinux.h + tracer_bpf*.go (+ .o)
//	go build -tags ebpf ./...         # build with eBPF support
//
// The default build (no tag) uses the stub in stub.go.
package ebpf

//go:generate sh -c "command -v bpftool >/dev/null && bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../../bpf/vmlinux.h"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags ebpf tracer ../../bpf/tracer.c -- -I../../bpf
