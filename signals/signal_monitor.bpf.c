// signal_monitor.bpf.c
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <bpf/bpf.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdbool.h>

//#include "vmlinux.h"

//struct {
// __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
// __uint(max_entries, 1);
// __type(key, __u32);
// __type(value, sizeof(int));
//} values SEC(".maps");



SEC("tracepoint/signal/signal_generate")
//SEC("tracepoint/signal/signal_deliver")
int signal_generate(struct trace_event_raw_signal_generate *ctx) {

//SEC("tracepoint/syscalls/sys_exit_kill")
//int kill_exit(struct trace_event_raw_sys_exit *ctx){

    bpf_printk("ESTA CAPTANDO SINAIS!!!\n");

    return 0;
}

char LICENSE[] SEC("license") = "GPL"; 
