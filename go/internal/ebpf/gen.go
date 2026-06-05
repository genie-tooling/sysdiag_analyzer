// Package ebpf traces process exec/exit via eBPF and attributes events to units.
//
// The generated bindings (tracer_bpf*.go + .o) are committed, so the default
// `go build -tags ebpf` needs no toolchain. REgeneration (only when editing
// bpf/tracer.c) needs clang + bpftool + libbpf headers (libbpf-dev). bpftool
// dumps vmlinux.h; -no-strip avoids a dependency on llvm-strip.
//
//	go generate ./...                 # produces vmlinux.h + tracer_bpf*.go (+ .o)
//	go build -tags ebpf ./...         # build with eBPF support
//
// The default build (no tag) uses the stub in stub.go.
package ebpf

//go:generate sh -c "command -v bpftool >/dev/null && bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../../bpf/vmlinux.h"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -tags ebpf tracer ../../bpf/tracer.c -- -I../../bpf
