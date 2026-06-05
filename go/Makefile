BIN ?= sysdiag-analyzer
PKG := ./cmd/sysdiag-analyzer

.PHONY: build ebpf ebpf-gen test vet fmt clean

# Default: static, CGo-free binary (eBPF stubbed, LSTM excluded).
build:
	CGO_ENABLED=0 go build -o $(BIN) $(PKG)

# eBPF build: uses the committed bpf2go bindings (internal/ebpf/tracer_bpf*.{go,o}),
# so this needs only Go — no clang/bpftool. Runtime needs root + a BTF kernel.
ebpf:
	CGO_ENABLED=0 go build -tags ebpf -o $(BIN) $(PKG)

# Regenerate the eBPF bindings from bpf/tracer.c, then build. Only needed when
# editing the BPF C. Requires clang + bpftool + libbpf headers (libbpf-dev).
ebpf-gen:
	@command -v clang   >/dev/null 2>&1 || { echo "ERROR: clang not found.   Install: sudo apt install -y clang"; exit 1; }
	@command -v bpftool >/dev/null 2>&1 || { echo "ERROR: bpftool not found. Install: sudo apt install -y linux-tools-common linux-tools-$$(uname -r)"; exit 1; }
	@test -e /usr/include/bpf/bpf_helpers.h || { echo "ERROR: libbpf headers not found. Install: sudo apt install -y libbpf-dev"; exit 1; }
	go generate ./...
	CGO_ENABLED=0 go build -tags ebpf -o $(BIN) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w ./cmd ./internal

# Remove the binary and regenerated vmlinux.h (keeps committed bindings).
clean:
	rm -f $(BIN) bpf/vmlinux.h
