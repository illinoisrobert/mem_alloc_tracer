#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "hello.skel.h"
#include "mem_alloc_tracer.skel.h"
#include "mem_alloc_tracer.h"

struct user_ring_buffer *user_ringbuf = NULL;

static int handle_event(void *ctx, void *data, size_t data_sz) {
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-5s %-16s %-7d\n", ts, "SIGN", e->command, (int)e->pid);

	return 0;
}

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

int main(void)
{
	struct mem_alloc_tracer_bpf *obj;
	struct ring_buffer *rb = NULL;
	int err = 0;

	struct rlimit rlim = {
		.rlim_cur = 512UL << 20,
		.rlim_max = 512UL << 20,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err) {
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}


	obj = mem_alloc_tracer_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = mem_alloc_tracer_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object %d\n", err);
		goto cleanup;
	}

	obj->bss->reporter_pid = getpid();

	err = mem_alloc_tracer_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	int map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj->obj, "events"));
	rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);

	while(true) {
		ring_buffer__poll(rb, 100);
	}

	ring_buffer__free(rb);
cleanup:
	mem_alloc_tracer_bpf__destroy(obj);
	return err != 0;
}
