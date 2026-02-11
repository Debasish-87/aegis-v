// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Standard types for absolute compatibility
typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned long long u64;

// --- KERNEL STRUCT SHIMS ---
// Yeh definitions compiler ke liye hain taaki "incomplete definition" error na aaye.
// CO-RE (Compile Once - Run Everywhere) attribute ke saath.

struct ns_common {
    unsigned int inum;
};

struct mnt_namespace {
    struct ns_common ns;
};

struct nsproxy {
    struct mnt_namespace *mnt_ns;
};

struct task_struct {
    struct nsproxy *nsproxy;
    struct task_struct *real_parent;
    int tgid;
} __attribute__((preserve_access_index));

// Event struct: Go side ke struct (Event) se bit-by-bit match karta hai
struct event {
    u32 pid;
    u32 ppid;      // Parent PID: Kaunsa process ise trigger kar raha hai
    u32 uid;       // User ID: 0 (root) hai ya normal user
    u32 mnt_ns;    // Mount Namespace: Container identification key
    u8 comm[16];   // Command name
};

// 1. Ring Buffer Map: Kernel-to-User communication
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} rb SEC(".maps");

// 2. Filter Map: Specific Container PIDs monitoring ke liye
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);   
    __type(value, u32); 
} filter_map SEC(".maps");

// SEC Definition: Hooking into 'execve' system call entry
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 uid = bpf_get_current_uid_gid();

    // Filter out PID 0 (Idle process)
    if (pid == 0) return 0;

    // Current task pointer uthao
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 mnt_ns_id = 0;

    // Namespace information safely read karo using CO-RE logic
    BPF_CORE_READ_INTO(&mnt_ns_id, task, nsproxy, mnt_ns, ns.inum);

    // Current command name capture karo
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // --- AGGRESSIVE NOISE FILTERING ---
    // VS Code (code)
    if (comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'e') return 0;
    // Go Language Server (gopls)
    if (comm[0] == 'g' && comm[1] == 'o' && comm[2] == 'p' && comm[3] == 'l') return 0;
    // Apt checks
    if (comm[0] == 'a' && comm[1] == 'p' && comm[2] == 't') return 0;
    // Update notifier
    if (comm[0] == 'u' && comm[1] == 'p' && comm[2] == 'd' && comm[3] == 'a') return 0;
    // Monitoring scripts
    if (comm[0] == 'c' && comm[1] == 'p' && comm[2] == 'u') return 0;
    // System utilities
    if (comm[0] == 'n' && comm[1] == 'i' && comm[2] == 'c' && comm[3] == 'e') return 0;
    if (comm[0] == 'i' && comm[1] == 'o' && comm[2] == 'n' && comm[3] == 'i') return 0;

    struct event *e;

    // 1. Space reserve karo Ring Buffer mein
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0; 
    }

    // 2. Metadata fill karo
    e->pid = pid;
    e->uid = uid;
    e->mnt_ns = mnt_ns_id;

    // Parent PID fetch karo safely
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    
    // Copy command name securely
    for (int i = 0; i < 16; i++) {
        e->comm[i] = comm[i];
    }

    // 3. Submit event to User Space (Go Engine)
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";