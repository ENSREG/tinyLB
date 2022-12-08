#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct eth_hdr {
    __u8 dst[6];
    __u8 src[6];
    __u16 type;
};

struct ip_hdr {
    __u8 hlen_version;
    __u8 tos;
    __u16 len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

struct tcp_hdr {
    __u16 sport;
    __u16 dport;
    __u32 seq;
    __u32 ack_seq;
    __u8 hlen;
    __u8 flags;
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
};

struct backend_entry {
    __u32 addr;
    __u16 port;
};

struct bpf_map_def SEC("maps") backend_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct backend_entry),
    .max_entries = 2,
};


SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct eth_hdr *eth = data;

    // Check if the packet is an IP packet
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }
    if (eth->type != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Check if the packet is a TCP packet
    struct ip_hdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // Route the packet to the appropriate backend server
    struct tcp_hdr *tcp = data + sizeof(*eth) + sizeof(*ip);
    int key = ntohs(tcp->dport);
    struct backend_entry *entry = bpf_map_lookup_elem(&backend_map, &key);
    if (entry == NULL) {
        return XDP_DROP;
    }

    // Update the IP header
    ip->daddr = entry->addr;
    ip->check = 0;
    ip->check = bpf_csum16((__u16 *)ip, sizeof(*ip));

    // Update the TCP header
    tcp->dport = entry->port;
    tcp->check = 0;
    tcp->check = bpf_csum_diff((__u16 *)tcp, sizeof(*tcp), (__u16 *)ip, sizeof(*ip), 0);

    // Forward the packet to the destination
    return bpf_redirect_map(&backend_map, key, 0);
}