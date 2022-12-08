#include "xdp_lb_kern.h"
// #include "xdp_lb_user.h"

#define IP_ADDRESS(x) (unsigned int)(192 + (17 << 8) + (0 << 16) + (x << 24))
#define BACKEND_A 2
#define BACKEND_B 3
#define CLIENT 4
#define LB 5

// struct bpf_map_def SEC("maps") my_map = {
//     .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//     .key_size = sizeof(int),
//     .value_size = sizeof(__u32),
//     .max_entries = 128,
// };

SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_printk("got something");

    // struct S trace;
    // int ret;
    // trace.time = bpf_ktime_get_ns();
    // ret = bpf_perf_event_output(ctx, &my_map, 0, &trace, sizeof(trace));
    // if (ret)
    //     bpf_printk("perf_event_output failed: %d\n", ret);

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

    bpf_printk("Got TCP packet from %x", iph->saddr);

    if (iph->saddr == IP_ADDRESS(CLIENT))
    {
        char be = BACKEND_A;
        if (bpf_ktime_get_ns() % 2)
            be = BACKEND_B;

        iph->daddr = IP_ADDRESS(be);
        eth->h_dest[5] = be;
    }
    else
    {
        iph->daddr = IP_ADDRESS(CLIENT);
        eth->h_dest[5] = CLIENT;
    }
    iph->saddr = IP_ADDRESS(LB);
    eth->h_source[5] = LB;

    iph->check = iph_csum(iph);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
