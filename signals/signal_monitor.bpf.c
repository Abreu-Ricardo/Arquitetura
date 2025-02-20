#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Structure to send event data to user space
struct signal_event {
    pid_t pid;   // Process receiving the signal
    int sig;   // Signal number
    int uid;   // User ID of sender
};

// Define a ring buffer map for communication with user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// Tracepoint for signal generation
SEC("tracepoint/signal/signal_generate")
int trace_signal_generate(struct trace_event_raw_signal_generate *ctx) {
    struct signal_event *event;
    struct task_struct *task;
    int pid = 0;

    // Reserve space in the ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0; // Drop event if the buffer is full
    }

    // Read the signal number
    event->sig = ctx->sig;

    // Read the task_struct pointer safely
    //bpf_probe_read_kernel(&task, sizeof(task), &ctx->t);

    // Read the PID from task_struct safely
    //bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    event->pid = pid;

    // Get the sender's UID
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Debug output (visible in trace_pipe)
    bpf_printk("Signal %d sent to PID %d (UID %d)", event->sig, event->pid, event->uid);

    // Submit event to the ring buffer
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
