caminho /usr/src/linux-source-6.8.0/linux-source-6.8.0-errado/kernel/bpf.h

/*****************MINHA FUNC****************************/
BPF_CALL_0(bpf_print_pid)
{
    printk(KERN_INFO "BPF Process ID: %d\n", current->pid);
    return current->pid;
}

static const struct bpf_func_proto bpf_print_pid_proto = {
    .func       = bpf_print_pid,
    .gpl_only   = false,
    .ret_type   = RET_INTEGER,
};
/***********************************************/

