#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>


// Define the BPF map
struct bpf_map_def backend_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct backend_entry),
    .max_entries = 2,
};

// Load the BPF program
int main(int argc, char *argv[])
{
    // Load the BPF object file
    char filename[256];
    sprintf(filename, "%s_kern.o", argv[0]);
    int prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, filename, 0);
    if (prog_fd < 0) {
        printf("Failed to load BPF program: %s\n", strerror(-errno));
        return 1;
    }

    // Attach the BPF program to an interface
    const char *ifname = argc > 1 ? argv[1] : "lo";
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        printf("Invalid interface name: %s\n", ifname);
        return 1;
    }
    int ret = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    if (ret < 0) {
        printf("Failed to attach BPF program to interface: %s\n", strerror(-errno));
        return 1;
    }

    // Wait for a key press
    printf("Press any key to update the BPF map...\n");
    getchar();

    // Define the new backend server entry
    struct backend_entry entry = {
        .addr = inet_addr("192.168.1.1"),
        .port = htons(8080),
    };

    // Update the BPF map
    int key = 123;
    ret = bpf_map_update_elem(&backend_map, &key, &entry, 0);
    if (ret < 0) {
        printf("Failed to update BPF map: %s\n", strerror(-errno));
        return 1;
    }

    // Wait for another key press
    printf("Press any key to stop the program...\n");
    getchar();

    // Detach the BPF program from the interface
    ret = bpf_set_link_xdp_fd(ifindex, -1, 0);
    if (ret < 0) {
        printf("Failed to detach BPF program from interface: %s\n", strerror(-errno));
        return 1;
    }

    return 0;
}