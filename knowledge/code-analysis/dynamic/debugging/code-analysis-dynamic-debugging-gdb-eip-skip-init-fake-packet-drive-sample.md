---
id: code-analysis-dynamic-debugging-gdb-eip-skip-init-fake-packet-drive-sample
title: GDB 强制驱动无法运行的样本：改 EIP 跳过 fork/pcap 初始化失败并手工构造数据包喂入核心处理函数
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: gdb-eip-skip-init-fake-packet-drive
aliases:
- GDB 改 EIP 绕过异常
- 样本无法运行时的强制调试
- 伪造数据包喂入处理函数
- 绕过 fork 失败调试
- 绕过 pcap_findalldevs 失败
tags:
- reverse
- gdb
- debugging
- malware
- freebsd
- packet
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V643
  verified_at: '2026-11-13T02:28:34+08:00'
  notes: 已对照原文与19张图逐图核对：GDB序列(b *0x080495F4、b *0x08049906→set $eip=0x0804990B、b *0x08049A9B、ebx=0xffbfed00、eip=0x08050BC0、0x08051AE9/0x08051AEE断点、x/10xw $esp)与原文及截图11/14一致；伪包set {int}写入值与原文hex一致，辅助Go脚本一致；dedup仅命中自身，相关卡为异构QEMU调试与IDA fork卡，非同链。未实际运行样本验证。
---

## 一句话结论

恶意样本因运行环境不匹配（`fork` 失败、`pcap_findalldevs` 取不到网卡）在进入核心功能前静默退出时，不必等环境完全适配：用 GDB `set $eip=<下一条指令>` 跳过失败调用，再把一个真实抓包的 IP 数据写进可写内存（`set {int}($ebx+off)=...`）、强制跳到数据包处理函数入口，即可让样本在“半残”状态下执行到通信解密与指令分发等核心代码，完成行为分析。

## 原理

- 样本启动阶段执行与环境强相关的初始化（`fork` 子进程、`setuid`、libpcap `pcap_findalldevs/pcap_open_live` 选网卡）；老版本 FreeBSD 样本运行在新系统或受限容器里这些调用失败，代码走错误分支直接 `return/exit`，表现为 `ps` 看不到进程、控制端也连不上，且无报错。
- 这些初始化只为“准备后续核心逻辑的输入”，核心的数据包处理函数并不依赖它们自身的返回值，只依赖传入的数据指针/长度。因此可以人为跳过初始化失败点，手工构造输入。
- 跳过失败的 `call` 时把 `eip` 改成调用后的下一条指令，保持栈上参数与返回地址布局不变（只跳过被调函数），不会破坏堆栈平衡；随后在可写内存中按样本期望的结构写入抓包载荷（按 4 字节小端 `set {int}`），再强制跳到处理函数入口。
- 处理函数入口可以通过通信函数（`recvfrom`/libpcap 回调）交叉引用或数据包特征十六进制（如魔数/校验和常量）搜索定位；调试时在解密函数下断点确认载荷被正确消费。
- 适用前提是样本与 GDB 同架构、同 OS（或可用 QEMU user-mode 模拟），且核心函数地址/寄存器传参约定已通过静态分析确认。

## 触发条件

- 样本因 `fork`/网卡枚举/权限等环境调用失败，在核心功能前退出；
- 已有可用的抓包载荷（真实通信样本）作为输入；
- GDB 能在目标系统上调试该二进制，且已知核心处理函数地址与输入传参寄存器。

## 利用步骤

1. `set follow-fork-mode child`（样本会 fork），`set disassembly-flavor intel`，在 `start` 与失败调用处下断点。
2. 运行到 `call fork` 处，`set $eip=<call 的下一条指令>` 跳过；`ni` 观察程序继续。
3. 运行到 `pcap_findalldevs` 失败分支前，`set $ebx=<可写缓冲区地址>`，`set $eip=<数据包处理函数入口>`，`ni` 进入核心函数。
4. 用 `set {int}($ebx+0x0)=0x...` 等逐 4 字节写入抓取的 IP 包（注意小端），在后续解密函数处下断点，`c` 观察解密结果。
5. 若样本需要主动发包验证响应，可按其 libnet 构包函数参数自写发送程序模拟。

## PoC

FreeBSD x86 样本（seconddate 1.7.0.3）的 GDB 序列（节选）：

```gdb
set follow-fork-mode child
set disassembly-flavor intel
b *0x080495F4
r
b *0x08049906          # fork 调用处
c
set $eip=0x0804990B    # 跳过 fork，落到下一条指令
ni
b *0x08049A9B          # pcap 初始化失败分支
c
set $ebx=0xffbfed00
set $eip=0x08050BC0    # 强制进入数据包处理函数
ni
set {int}($ebx+0x0)=0x54000045   # 抓到的 IP 包按 4 字节小端写入
set {int}($ebx+0x4)=0x0040c8bd
# ... 其余 4 字节组 ...
b *0x08051AE9          # UDP 载荷解密函数
c
x /10xw $esp
```

把 pcap 十六进制批量转成 `set {int}` 指令的辅助脚本（Go，原文）：

```go
hex_data, _ := hex.DecodeString("45000054bdc840004011fe78...")
for i := 0; i < len(hex_data); i += 4 {
    aa := bits.ReverseBytes32(uint32(BytesToInt(hex_data[i:i+4])))
    fmt.Printf("set {int}($ebx+0x%x)=0x%s\n", i, hex.EncodeToString(IntToBytes(int(aa))))
}
```

## 变体与关联

- 变体：无法运行的原因换成 `setuid` 失败、缺库、反调试检测时，同样可 `set $eip` 跳过对应分支，或用 `LD_PRELOAD` 伪造库函数返回值。
- 变体：跨架构样本用 QEMU user-mode + `gdbserver` 远程调试，再套用同一“跳失败初始化 + 伪造输入”思路。
- 关联：[[code-analysis-dynamic-debugging-heterogeneous-arch-qemu-gdb-multiarch]]——异构架构 GDB 调试环境。
- 关联：[[tools-ida-fork-child-loop-patch-attach]]——fork 型样本的调试附加技巧（IDA 侧）。

## 检测与防御

- 该卡为分析手法，不针对目标系统防护；对防守方而言，样本依赖的 pcap/libnet 行为本身就是检测点：异常进程调用 `pcap_findalldevs`/`pcap_open_live`、原始套接字嗅探、libnet 构包。
- 防御：限制普通用户原始套接字与 BPF 设备权限，监控长期嗅探 UDP 的进程。
