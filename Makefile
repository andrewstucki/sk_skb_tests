LLVM_PATH ?= /usr/local/opt/llvm/bin

CLANG ?= $(LLVM_PATH)/clang
STRIP ?= $(LLVM_PATH)/llvm-strip
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
GOOS := linux
GOLDFLAGS := -s -w

bpf/bpf_bpfel.go: export BPF_STRIP := $(STRIP)
bpf/bpf_bpfel.go: export BPF_CLANG := $(CLANG)
bpf/bpf_bpfel.go: export BPF_CFLAGS := $(CFLAGS)
bpf/bpf_bpfel.go: bpf/bpf.c
	go generate ./...

.PHONY: generate
generate: bpf/bpf_bpfel.go

sk_skb_tests: export GOOS := $(GOOS)
sk_skb_tests: generate
	go build -ldflags "$(GOLDFLAGS)"

clean:
	@rm -f bpf/bpf_* sk_skb_tests

.DEFAULT_GOAL := sk_skb_tests