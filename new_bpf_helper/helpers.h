caminho /usr/src/linux-source-6.8.0/linux-source-6.8.0-errado/kernel/bpf/helpers.c

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

/*****************MINHA FUNC****************************/
// Declarar fora da funcao, no escopo global

static struct task_struct *task;
static struct kernel_siginfo info = {
        .si_signo = SIGUSR1,
        .si_code  = SI_QUEUE,
        .si_int   = 2025,
};

static struct pid *PID;

// Adiciona o caso de quando chamarem a funcao para retornar para a funcao nova
bpf_base_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
        switch (func_id) {
        // MINHA_FUNC
        case BPF_FUNC_minha_func:
                return &bpf_minha_func_proto;

	// ...
}

BPF_CALL_1(bpf_minha_func, int, pid)
{
        //int temp=0;
        //temp = pid + 1;
        //return temp;

        //struct task_struct *task;


        ////struct siginfo info;
        //struct kernel_siginfo info;

        ////memset(&info, 0, sizeof(struct siginfo));
        //
        //memset(&info, 0, sizeof(struct kernel_siginfo));
        //info.si_signo = SIGUSR1;
        //info.si_code  = SI_QUEUE;
        //info.si_int   = 2025;


        //rcu_read_lock();
        PID = find_vpid( pid );
        //task = pid_task(find_vpid(pid), PIDTYPE_PID);

        //task = pid_task( PID  , PIDTYPE_PID);
        //task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
        task = get_pid_task(PID, PIDTYPE_PID);
        if (task != NULL){
                send_sig_info(SIGUSR1, &info, task);

                // Se task != sinal enviado e returno 0 que deu certo
                //rcu_read_unlock();
                return 0;
        }

        // Caso task seja == NULL deu errado
        //rcu_read_unlock();
        return -1;
}

const struct bpf_func_proto bpf_minha_func_proto = {
        .func           = bpf_minha_func,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_ANYTHING,
};

/***********************************************/

caminho --> kernel/linux/bpf.h

// MINHA_FUNC
extern const struct bpf_func_proto bpf_minha_func_proto;


/***********************************************/
caminho --> kernel/uapi/linux/bpf.h

// Adiciona a funcao na lista de helpers do sistema

FN(minha_func, 212, ##ctx)                      \


/***********************************************/
caminho no diretorio raiz do sistema nao do kernel tree --> /usr/include/bpf/bpf_helper_defs.h

// Declara o cabecalho da funcao para ser usada pelo sistema
static __u64 (* const bpf_minha_func)(int pid) = (void *) 212;

