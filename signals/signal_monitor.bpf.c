#include "vmlinux.h"


#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>


__u32 cont=0;

// Structure to send event data to user space
struct signal_event {
    pid_t pid;   // Process receiving the signal
    int sig;     // Signal number
    int uid;     // User ID of sender
};

// Define a ring buffer map for communication with user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// Tracepoint for signal generation
SEC("tracepoint/signal/signal_generate")
int trace_signal_generate(struct trace_event_raw_signal_generate *ctx) {
    
    //bpf_printk("VALOR --> %d\n", ctx->sig);
    //if ( ctx->sig == 10 ){
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

        // Read the PID from task_struct safely
        //bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
        event->pid = ctx->pid;
 
        // Debug output (visible in trace_pipe)
        /*bpf_printk("Sinal %d enviado para o PID:%d | %d \n", event->sig, 
                                                          event->pid, 
                                                        cont++);
        */

        bpf_printk("Sinal %d enviado para o PID:%d |group: %d |code %d| resul %d", event->sig, 
                                                                                   event->pid, 
                                                                                   ctx->group,
                                                                                   ctx->code,
                                                                                   ctx->result);


        // Submit event to the ring buffer
        bpf_ringbuf_submit(event, 0);
        //return 0;
    //}

    //bpf_printk("Outro sinal...\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
