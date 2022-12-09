#include "xdp_lb_kern.h"

#define IP_ADDRESS(x) (unsigned int)(192 + (17 << 8) + (0 << 16) + (x << 24))
#define BACKEND_A 2
#define BACKEND_B 3
#define CLIENT 4
#define LB 5
#define HTTP_PORT 80

SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_ABORTED;

    int flag = 1;

    if (iph->saddr == IP_ADDRESS(CLIENT) && bpf_ntohs(tcph->dest) == HTTP_PORT)
    {
        bpf_printk("Got http request from %x", iph->saddr);
        char dst = BACKEND_A;
        if (bpf_ktime_get_ns() % 2)
            dst = BACKEND_B;

        iph->daddr = IP_ADDRESS(dst);
        eth->h_dest[5] = dst;
    } else if (iph->saddr == IP_ADDRESS(BACKEND_A) || iph->saddr == IP_ADDRESS(BACKEND_B))
    {
        bpf_printk("Got the http response from backend [%x]: forward to client %x", iph->saddr, iph->daddr);
        iph->daddr = IP_ADDRESS(CLIENT);
        eth->h_dest[5] = CLIENT;
    } else {
        flag = 0;
    }

    if (!flag) {
        return XDP_PASS;
    }

    iph->saddr = IP_ADDRESS(LB);
    eth->h_source[5] = LB;

    iph->check = iph_csum(iph);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
