
// Define a struct to hold event data
struct event {
	void* alloc_ip;
	__u64 pid;
	void* obj_va_ptr;
	__s64 size;
	__u64 alloc_index;
	__u64 free_index;
	void* free_ip;
	int alloc_type;
	char command[256];
	char slabname[256];
	void* new_alloc_type;
};
