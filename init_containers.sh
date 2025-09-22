#!/bin/bash

set -o pipefail

SIGSHARED=$(pwd)
export SIGSHARED
echo "$SIGSHARED"

string="$1"

if [ "$string" = "up" ]; then
    sudo ip netns add c1; 
    sudo ip netns add c2; 
    sudo ip netns add c3; 
    sudo ip netns add c4; 

    # Servidor --> R1
    # 10.10.1.1 --> 192.168.1.2
    #sudo ip link add veth1 type veth peer name veth2; 
    sudo ip link add veth1 netns c1 type veth peer name veth2 netns c2;


    # R1 --> N3
    # 10.10.2.3 --> 192.168.2.4
    #sudo ip link add veth3 type veth peer name veth4;
    sudo ip link add veth3 netns c2 type veth peer name veth4 netns c3;

    # N3 --> N4
    # 10.10.3.5 --> 192.168.3.6
    #sudo ip link add veth5 type veth peer name veth6;
    sudo ip link add veth5 netns c3 type veth peer name veth6 netns c4;


    # N4 --> Servidor
    # 10.10.4.7 --> 192.168.4.8
    #sudo ip link add veth5 type veth peer name veth6;
    sudo ip link add veth7 netns c4 type veth peer name veth8 netns c1;


    #####################################################

    # Movendo as veth para os netspaces
    # N1 --> veth1 e veth6 
    # N1 <---> N2
    # N1 <--_> N3                         
    #sudo ip link set veth1 netns n1;
    #sudo ip link set veth6 netns n1;
    #
    ## N2 --> veth 2 e veth3
    ## N2 <---> N1 
    ## N2 <---> N3          
    #sudo ip link set veth2 netns n2;
    #sudo ip link set veth3 netns n2;
    #
    ## N3 --> veth4 e veth 5
    ## N3 <---> N1 
    ## N3 <---> N2
    #sudo ip link set veth4 netns c3;
    #sudo ip link set veth5 netns c3;


    # Atribuindo IP para cada veth
    # Servidor
    sudo ip netns exec c1 ip addr add 10.10.10.2/24 dev veth1;
    sudo ip netns exec c1 ip addr add 40.40.40.3/24 dev veth8;

    # R1
    sudo ip netns exec c2 ip addr add 10.10.10.1/24 dev veth2;
    sudo ip netns exec c2 ip addr add 20.20.20.1/24 dev veth3;

    # N3
    sudo ip netns exec c3 ip addr add 20.20.20.2/24 dev veth4;
    sudo ip netns exec c3 ip addr add 30.30.30.2/24 dev veth5;

    # N4
    sudo ip netns exec c4 ip addr add 30.30.30.3/24 dev veth6;
    sudo ip netns exec c4 ip addr add 40.40.40.2/24 dev veth7;


    # Levantando os loopbacks e as veths 
    sudo ip netns exec c1 ip link set lo up;
    sudo ip netns exec c1 ip link set dev veth1 up;
    sudo ip netns exec c1 ip link set dev veth8 up;

    sudo ip netns exec c2 ip link set lo up;
    sudo ip netns exec c2 ip link set dev veth2 up;
    sudo ip netns exec c2 ip link set dev veth3 up;

    sudo ip netns exec c3 ip link set lo up;
    sudo ip netns exec c3 ip link set dev veth4 up;
    sudo ip netns exec c3 ip link set dev veth5 up;

    sudo ip netns exec c4 ip link set lo up;
    sudo ip netns exec c4 ip link set dev veth6 up;
    sudo ip netns exec c4 ip link set dev veth7 up;


    # Habilitando o roteamento nos containers
    sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';

    sudo ip netns exec c1 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
    sudo ip netns exec c2 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
    sudo ip netns exec c3 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'; 
    sudo ip netns exec c4 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'; 

    # Desligando o reverse path filtering das interfaces
    sudo ip netns exec c1 sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth8/rp_filter'
    sudo ip netns exec c2       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth2/rp_filter'
    sudo ip netns exec c2       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth3/rp_filter'
    sudo ip netns exec c3       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth4/rp_filter'
    sudo ip netns exec c3       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth5/rp_filter'
    sudo ip netns exec c4       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth6/rp_filter'
    sudo ip netns exec c4       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth7/rp_filter'


    ## 0.0.0.0 --> Sinaliza para como gateway padrao
    # Rotear pelo R1: Servidor --> R1 --> N3
    #                       N3 --> R1 --> Servidor
    sudo ip netns exec c1 sh -c 'route add -net 0.0.0.0/0 gw 10.10.10.1 ';  
    sudo ip netns exec       c3 sh -c 'route add -net 0.0.0.0/0 gw 20.20.20.1 '; 


    # Rotear pelo N4: Servidor --> N4 --> N3
    #                       N3 --> N4 --> Servidor
    #sudo ip netns exec c1 sh -c 'route add -net 0.0.0.0/0 gw 40.40.40.2 ';  
    #sudo ip netns exec       c3 sh -c 'route add -net 0.0.0.0/0 gw 30.30.30.3 '; 

    # Atribuindo o MAC estaticamente para atribuir o arp
    sudo ip netns exec  c1 sh -c 'ifconfig veth1 hw ether 00:11:22:33:44:11'
    sudo ip netns exec  c1 sh -c 'ifconfig veth8 hw ether 00:11:22:33:44:88'
    sudo ip netns exec  c2 sh -c 'ifconfig veth2 hw ether 00:11:22:33:44:22'
    sudo ip netns exec  c2 sh -c 'ifconfig veth3 hw ether 00:11:22:33:44:33'
    sudo ip netns exec  c3 sh -c 'ifconfig veth4 hw ether 00:11:22:33:44:44'
    sudo ip netns exec  c3 sh -c 'ifconfig veth5 hw ether 00:11:22:33:44:55'

    # Atribuindo ARP esticamente
    sudo ip netns exec c1 sh -c 'arp -s 10.10.10.1 00:11:22:33:44:22'
    sudo ip netns exec c2 sh -c 'arp -s 10.10.10.2 00:11:22:33:44:11'
    sudo ip netns exec c2 sh -c 'arp -s 20.20.20.2 00:11:22:33:44:44'
    sudo ip netns exec c3 sh -c 'arp -s 20.20.20.1 00:11:22:33:44:33'

    
    # Pegando caminho absoluto da raiz do github
    #gnome-terminal --tab -- sh -c 'sudo ip netns exec c1 sh -c 'sudo source init_containers.sh';exec bash; '
    #sudo ip netns exec c1 sh -c 'sudo source init_containers.sh && echo $SIGSHARED'
    #sudo ip netns exec c2 sh -c 'source init_containers.sh'
    #sudo ip netns exec c3 sh -c 'source init_containers.sh'


    # Aqui vai criar um link no dir dados para o bpffs
    sudo mount -t bpf bpffs /sys/fs/bpf
    sudo mount --bind /sys/fs/bpf $(pwd)/dados;
    #sudo mount -t bpf bpffs $(pwd)/dados 
    #sudo mkdir -p /sys/fs/bpf/sigshared/
    #sudo mount -t bpf bpffs /bpffs


    #sudo ip netns exec c3 sh -c 'ethtool -K veth4 gro on' 
    #sudo ip netns exec c3 sh -c 'ethtool -K veth5 gro on' 

    sleep 1
    echo "Servidor--> sudo ip netns exec c1 bash";
    echo "      R1--> sudo ip netns exec c2 bash";
    echo "      N3--> sudo ip netns exec c3 bash";
    echo "      N4--> sudo ip netns exec c4 bash";

    echo -e "\n +++ Use dentro de cada container antes de entrar nos dirs: < source init_containers.sh > +++"

    echo -e "\n\n(garantir que bpf fs esteja montado)--> mount -t bpf bpffs /sys/fs/bpf"
    echo -e "mount -t debugfs none /sys/kernel/debug --> Para rodar programas eBPF que usam vmlinux.h"
    echo "(configurar ARP estaticamente)      -->sudo arp -s 10.10.10.1 AA:BB:CC:DD:EE:FF"

    echo -e "Para isolar a CPU do kernel e desabilitar threads do nucleo --> sudo vim /etc/default/grub"
    echo -e "Buscar por: GRUB_CMDLINE_LINUX_DEFAULT='... isolcpus=3,4 nosmt'"
    echo -e "E por fim --> sudo update-grub"

    #echo -e "c1--> $(veth1_mac) $(veth8_mac)\nc2 --> $(veth2_mac) $(veth3_mac)\nc3 --> $(veth4_mac) $(veth5_mac)\n"
    #echo -e "c1--> $(veth1_mac) \n"

    # Precisa passar o nome da veth para poder pingar
    # Se nao, vai usar a veth que n tem par com a outra veth
    echo " "
    echo " "

    sleep 1
    gnome-terminal --tab -- bash -c " sudo ip netns exec c1 bash  "
    sudo ip netns exec c1 sh -c 'mount -t debugfs none /sys/kernel/debug'
    
    sleep 1
    gnome-terminal --tab -- bash -c " sudo ip netns exec c2 bash  "
    
    sleep 1
    gnome-terminal --tab -- bash -c " sudo ip netns exec c3 bash  "

    sleep 1
    gnome-terminal --tab -- bash -c " sudo ip netns exec c4 bash  "


    #gnome-terminal --tab -- sh -c "bash;"
    #echo "Para pingar--> ping 10.10.10.* -c 3 -I <nome_veth>"
    #echo "Para alterar a exec entre apenas host e entre containers alterar os seguintes arquivos"
    #echo "/bib/teste_bib.c= carrega_ebpf() remove_ebpf()"
    #echo "/eBPF/espaco_kernel.c= comentar atributo pinning do mapa"
    #
    #echo "/gerenciador_mem/consumidor.c= alterar caminho de mapa_fd"

fi
######################################


######################################
if [ "$1" == "down" ]; then
    sudo ip netns delete c1;  #server
    sudo ip netns delete c2;  #client
    sudo ip netns delete c3;  #host
    sudo ip netns delete c4;  #host

    # Para desvicular o dir /dados de /sys/fs/bpf
    sudo umount $(pwd)/dados


    sudo bash -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'

fi
