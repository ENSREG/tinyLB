# TinyLB (Tiny Load Balancer)

該專案受 [eBPF Summit 2021: An eBPF Load Balancer from scratch](https://www.youtube.com/watch?v=L3_AOFSNKK8) 啟發，並且修改自 [lb-from-scratch](https://github.com/lizrice/lb-from-scratch) 專案。

## 什麼是 TinyLB？

一個不到 100 行的 eBPF 程式，它利用 XDP 實作一個簡單的 HTTP load balancer。
TinyLB 依賴 [libbpf](https://github.com/libbpf/libbpf/tree/8bdc267e7b853ca08ed762b21fecc0e019ddc332)（commit: 8bdc267），開始前請先下載 libbpf：
```sh
cd tinyLB
git clone https://github.com/libbpf/libbpf.git
cd libbpf
git checkout 8bdc267
```


## 開始

首先，編譯 load balancer 所需要的 docker image：
```sh
cd tinyLB
./build_image.sh
```
編譯完成後，執行以下指令啟動測試環境：
```sh
cd compose
docker compose up
```

### 觀察 TinyLB 的輸出

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
