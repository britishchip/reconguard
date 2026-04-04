# Makefile for ReconGuard XDP project

# Tools
CLANG       ?= clang
BPFTOOL     ?= bpftool
CC          ?= gcc

# Flags
CFLAGS      := -O2 -Wall -Wextra -g
BPF_CFLAGS  := -O2 -g -target bpf \
               -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

# Files
BPF_SRC     := reconguard.bpf.c
BPF_OBJ     := reconguard.bpf.o
SKEL        := reconguard.skel.h
USER_SRC    := reconguard.c          # userspace file
USER_BIN    := reconguard                 # output binary name

# Default target
all: $(USER_BIN)

# 1. Compile BPF object (with BTF for skeleton + CO-RE)
$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 2. Generate skeleton from the BPF object
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name reconguard > $@

# 3. Compile userspace loader
$(USER_BIN): $(USER_SRC) $(SKEL)
	$(CC) $(CFLAGS) $< -o $@ -lbpf

# Clean generated files
clean:
	rm -f $(BPF_OBJ) $(SKEL) $(USER_BIN)

# Full rebuild
rebuild: clean all

# Phony targets
.PHONY: all clean rebuild run

# Optional: if you want to auto-generate vmlinux.h (uncomment if needed)
# vmlinux.h:
# 	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h