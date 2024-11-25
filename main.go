package main

import (
	"os"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

func IP_ADDRESS(d, c, b, a int) uint32 {
	return uint32(a + b<<8 + c<<16 + d<<24)
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("xdp_lb_kern.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	prog, err := bpfModule.GetProgram("tiny_lb")
	if err != nil {
		panic(err)
	}

	// TODO: support xdpgeneric
	// link, err := prog.AttachXDP("eth0")
	// if err != nil {
	// 	panic(err)
	// }
	// if link.FileDescriptor() == 0 {
	// 	os.Exit(-1)
	// }

	prog_map, err := bpfModule.GetMap("lb_map")
	if err != nil {
		panic(err)
	} else {
		clientIP := IP_ADDRESS(192, 17, 0, 4)
		backendAIP := IP_ADDRESS(192, 17, 0, 2)
		backendBIP := IP_ADDRESS(192, 17, 0, 3)
		lbIP := IP_ADDRESS(192, 17, 0, 5)

		c := uint32(4)
		a := uint32(2)
		b := uint32(3)
		lb := uint32(5)

		prog_map.Update(unsafe.Pointer(&c), unsafe.Pointer(&clientIP))
		prog_map.Update(unsafe.Pointer(&a), unsafe.Pointer(&backendAIP))
		prog_map.Update(unsafe.Pointer(&b), unsafe.Pointer(&backendBIP))
		prog_map.Update(unsafe.Pointer(&lb), unsafe.Pointer(&lbIP))
	}

	prog, err = bpfModule.GetProgram("capture_skb")
	if err != nil {
		panic(err)
	}
	link, err := prog.AttachGeneric()
	if err != nil {
		panic(err)
	}
	if link.FileDescriptor() == 0 {
		os.Exit(-1)
	}

	for {
		time.Sleep(10 * time.Second)
	}
}
