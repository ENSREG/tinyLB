#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <libbpf.h>
#include<signal.h>

struct bpf_object *obj;
int lb_map_fd;

void sig_handler(int signum){
    close(lb_map_fd);
    bpf_object__close(obj);
    printf("\nInside handler function\n");
}

int main() {

    printf("bpf load start\n");
    
    obj = bpf_object__open_file("xdp_lb_kern.o", NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 0;
    }

    /* load BPF program */
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }
    lb_map_fd = bpf_object__find_map_fd_by_name(obj, "lb_map");
    if (lb_map_fd < 0) {
			fprintf(stderr, "ERROR: no lb map found: %s\n",
				strerror(lb_map_fd));
			exit(EXIT_FAILURE);
	}

    printf("bpf load success\n");

    unsigned int client_ip = 0xC0110004;
    unsigned int backend_a_ip = 0xC0110002;
    unsigned int backend_b_ip = 0xC0110003;
    unsigned int lb_ip = 0xC0110005;

    unsigned int c = 4;
    unsigned int a = 2;
    unsigned int b = 3;
    unsigned int lb = 5;

    bpf_map_update_elem(lb_map_fd, &c, &client_ip, BPF_ANY);
    bpf_map_update_elem(lb_map_fd, &a, &backend_a_ip, BPF_ANY);
    bpf_map_update_elem(lb_map_fd, &b, &backend_b_ip, BPF_ANY);
    bpf_map_update_elem(lb_map_fd, &lb, &lb_ip, BPF_ANY);
    signal(SIGINT, sig_handler);
    for(;;){}

    return 0;

cleanup:
    close(lb_map_fd);
    bpf_object__close(obj);
}
