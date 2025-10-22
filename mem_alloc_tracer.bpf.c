#include "vmlinux.h"
// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "mem_alloc_tracer.h"



// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>

// #include <uapi/linux/ptrace.h>
// #include <linux/types.h>
// #include <linux/ptrace.h>
// #include <linux/bpf.h>
// #include <linux/ring_buffer.h>

// eBPF map to store events
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256*1024);
	// .type = BPF_MAP_TYPE_RINGBUF,
	// .max_entries = 256 * 1024,
} events SEC(".maps");

// Avoid watching this pid
volatile int reporter_pid = 0;

// Broadcast event function
static int broadcast_event(struct pt_regs *ctx) {
	int pid = bpf_get_current_pid_tgid() >> 32;
	struct event *e;

	bpf_printk("pid=%d, reporter_pid=%d\n", pid, reporter_pid);
	if(pid == reporter_pid) {
		return 0;
	}
	// Reserve space in ring buffer
	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	bpf_printk("sha-la-la");
	if (!e) {
		return 0;
	}

	// Populate event details
	e->alloc_ip = (void *)ctx->ip;
	e->pid = (pid_t)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);

	// Get current process name
	bpf_get_current_comm(e->command, sizeof(e->command));

	// Submit event to ring buffer
	bpf_ringbuf_submit(e, 0);

	return 0;
}

// Kprobe handlers for various memory allocation functions
SEC("kprobe/kmem_cache_alloc_noprof")
int BPF_KPROBE(kprobe_kmem_cache_alloc, struct kmem_cache *s, gfp_t flags) {
	return broadcast_event(ctx);
}

SEC("kprobe/__kmalloc_noprof")
int BPF_KPROBE(kprobe_kmalloc_noprof, size_t size, gfp_t flags) {
	return broadcast_event(ctx);
}

SEC("kprobe/__kmalloc_large_noprof")
int BPF_KPROBE(kprobe_kmalloc_large_noprof, size_t size, gfp_t flags) {
	return broadcast_event(ctx);
}


char LICENSE[] SEC("license") = "GPL";
