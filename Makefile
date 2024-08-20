TARGET = xdp_lb

BPF_TARGET = ${TARGET:=_kern}
USER_TARGET = ${TARGET:=_user}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

lb:
	docker exec -it lb bash

user: $(USER_TARGET)
$(USER_TARGET): %: %.c  
	gcc -Wall $(CFLAGS) -Ilibbpf/src -Ilibbpf/src/include/uapi -Llibbpf/src -o $@  \
	 $< -l:libbpf.a -lelf -lz

xdp: $(BPF_OBJ)
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/$(TARGET)
	# bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)

run: $(BPF_OBJ)
	./xdp_lb_user &
	bpftool net attach xdpgeneric name tiny_lb dev eth0
	sleep infinity

$(BPF_OBJ): %.o: %.c
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -Ilibbpf/src\
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror -emit-llvm \
	    -O2 -c -g \
		-o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

.PHONY: libbpf
libbpf:
	git clone https://github.com/libbpf/libbpf.git && \
	cd libbpf && \
	git checkout 8bdc267 && \
	cd src && \
	make

clean:
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/$(TARGET)
	rm $(BPF_OBJ)
	rm ${BPF_OBJ:.o=.ll}
