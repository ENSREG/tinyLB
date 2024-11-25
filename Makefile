TARGET = xdp_lb


BPF_TARGET = ${TARGET:=_kern}
USER_TARGET = ${TARGET:=_user}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

BASEDIR = $(abspath .)
OUTPUT = output
LIBBPF_INCLUDE_UAPI = $(abspath ./libbpf/include/uapi)
LIBBPF_SRC = $(abspath libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))
CLANG_BPF_SYS_INCLUDES := `shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'`
CGOFLAG = CC=clang CGO_CFLAGS="-I$(BASEDIR)/$(OUTPUT)" CGO_LDFLAGS="-lelf -lz $(LIBBPF_OBJ)"
STATIC=-extldflags -static

.PHONY: build
build: libbpf libbpf-uapi
	$(CGOFLAG) go build -ldflags "-w -s $(STATIC)" main.go

.PHONY: libbpf-uapi
libbpf-uapi: $(LIBBPF_SRC)
	UAPIDIR=$(LIBBPF_DESTDIR) \
		$(MAKE) -C $(LIBBPF_SRC) install_uapi_headers

.PHONY: libbpf
libbpf: $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch])
	CC="gcc" CFLAGS="-g -O2 -Wall -fpie" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install
	$(eval STATIC=-extldflags -static)

lb:
	docker exec -it lb bash

btf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux/vmlinux.h

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
	sleep 1 && bpftool net attach xdpgeneric name tiny_lb dev eth0
	sleep infinity

$(BPF_OBJ): %.o: %.c
	clang -S \
		-target bpf \
		-D __BPF_TRACING__ \
		-I vmlinux/ \
		-I libbpf/src \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror -emit-llvm \
		-O2 -c -g \
		-o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

dep:
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
