# TLB (Tiny Load Balancer)

This project is inspired by [eBPF Summit 2021: An eBPF Load Balancer from scratch](https://www.youtube.com/watch?v=L3_AOFSNKK8).

```
docker run --rm -it --privileged ianchen0119/lb:latest bash
```

## Observe the output from bpf program

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
