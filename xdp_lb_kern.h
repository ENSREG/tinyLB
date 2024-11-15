#ifndef XDP_LB_KERN_H
#define XDP_LB_KERN_H

#include "vmlinux.h"
#include <bpf_core_read.h> /* CO-RE */
#define BPF_NO_PRESERVE_ACCESS_INDEX
#include <bpf_helpers.h>
#include <bpf_endian.h>


#define ETH_P_IP 0x0800 /* Internet Protocol packet */

static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}
#endif /* XDP_LB_KERN_H */