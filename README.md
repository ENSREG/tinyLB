# TinyLB (Tiny Load Balancer)

該專案受 [eBPF Summit 2021: An eBPF Load Balancer from scratch](https://www.youtube.com/watch?v=L3_AOFSNKK8) 啟發，並且修改自 [lb-from-scratch](https://github.com/lizrice/lb-from-scratch) 專案。

## 什麼是 TinyLB？

一個不到 100 行的 eBPF 程式，它利用 XDP 實作一個簡單的 HTTP load balancer。
TinyLB 依賴 [libbpf](https://github.com/libbpf/libbpf/tree/8bdc267e7b853ca08ed762b21fecc0e019ddc332)（commit: 8bdc267），開始前請先下載 libbpf：
```sh
make dep
```


## 開始

首先，編譯 load balancer 所需要的 docker image 以及工具：
```sh
cd tinyLB
./build_image.sh
make user
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

### 將 BPF Program 附加到網路介面

位於 User Space 的 xdp_lb_user 已經幫我們完成 BPF program 的載入工作，我們可以進入 lb 容器檢查相關資訊：

```bash
$ docker exec -it lb bash
$ bpftool prog show
256: xdp  name tiny_lb  tag 38052a6ecf9edb21  gpl
        loaded_at 2023-09-08T08:21:01+0000  uid 0
        xlated 1544B  jited 921B  memlock 4096B  map_ids 47
        btf_id 164
```
在這個範例中，`256` 為 tinyLB 的 ID，使用 bpftool 即可將 tinyLB 附加到指定網卡上（目前 attach 的動作會被 make 腳本自動完成，所以下面步驟可以忽略）：
```bash
$ bpftool net attach xdpgeneric id 256 dev eth0
```
或是：
```bash
bpftool net attach xdpgeneric name tiny_lb dev eth0
```

TinyLB 將 loadbalancing rule 存放於 BPF Map 上，使用 bpftool 可以觀察 Map 的內容：
```bash
$ bpftool map show
47: hash  name lb_map  flags 0x0
        key 4B  value 4B  max_entries 64  memlock 8192B
        btf_id 164
$ bpftool map dump id 47
[{
        "key": 3,
        "value": 3222339587
    },{
        "key": 2,
        "value": 3222339586
    },{
        "key": 5,
        "value": 3222339589
    },{
        "key": 4,
        "value": 3222339588
    }
]
```
或是：
```bash
$ bpftool map dump name lb_map
```