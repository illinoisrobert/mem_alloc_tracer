#!/bin/sh -ex

sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/bpf -I . -c mem_alloc_tracer.bpf.c -o mem_alloc_tracer.bpf.o
sudo bpftool gen skeleton mem_alloc_tracer.bpf.o > mem_alloc_tracer.skel.h
clang -g -O2 -Wall -I . -c mem_alloc_tracer.c -o mem_alloc_tracer.o
clang -Wall -O2 -g mem_alloc_tracer.o -lbpf -lelf -lz -o mem_alloc_tracer
sudo ./mem_alloc_tracer
