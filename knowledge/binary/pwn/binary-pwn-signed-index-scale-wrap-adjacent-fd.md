---
id: binary-pwn-signed-index-scale-wrap-adjacent-fd
title: 符号检查遗漏 + 索引缩放回绕越界：uint64 0x800000000000000a 命中结构体相邻 dbus fd
type: scenario
domain: binary
path: binary/pwn
technique: signed-index-scale-wrap-oob
aliases:
- 符号转换越界
- conn_id 0x800000000000000a
- 索引缩放回绕
- int64 负数绕过上界检查
- 结构体相邻 fd
- IVI OP_RESP
tags:
- pwn
- integer
- signedness
- oob
- array-index
- scale-wrap
- fd
- ipc
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:52:52+08:00'
  notes: 已对照原文 autodiag 核对：OP_RESP conn_id=uint64→int64 只查 idx>9、0x800000000000000a*4 在 64 位回绕为 0x28=conn_fds[10]=dbus_sock_fd、借已认证 DBus socket 写裸 method call、再触发 RunUpdate/update runner 均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

C 服务把用户提交的 `uint64_t conn_id` 转成 `int64_t idx` 后只检查 `idx > MAX_CONN_SLOTS - 1`、不检查负数；攻击者提交 `0x800000000000000a`，按有符号数是负数可通过检查，而 x86-64 的 `[base + idx*4]` 有效地址计算在 64 位回绕后得到偏移 0x28，正好命中 `conn_fds[10]` 后面的 `dbus_sock_fd`，从而把任意数据写入服务内部已认证的 DBus 连接。

## 原理

- 目标结构体近似：
  ```c
  struct ServerState {
      int conn_fds[10];      // 40 字节
      int dbus_sock_fd;      // 紧邻 conn_fds[10]
      ...
  };
  ```
- 外部 `OP_RESP` 解析 `conn_id` 为 `uint64_t`，再转 `int64_t idx`，检查只有 `if (idx > MAX_CONN_SLOTS - 1) reject;`，缺少 `idx < 0`。
- 正常要访问 `conn_fds[10]`（即 `dbus_sock_fd`）需要 `idx=10`，会被上界检查拦下。
- 选择 `conn_id = 0x800000000000000a`：
  - 转成 `int64_t` 是 `-9223372036854775798`，小于 0，不满足 `idx > 9`，检查通过。
  - 编译器生成 `mov eax, DWORD PTR [rax + rdx*4]`。x86-64 有效地址是 64 位模 2^64 运算：`0x800000000000000a * 4 = 0x2000000000000028`，截断到 64 位为 `0x28`（40 字节），即 `conn_fds[10]`。
- 于是 `target_fd = st->conn_fds[idx]` 实际读到 `dbus_sock_fd`，后续 `send(target_fd, frame, payload_len, 0)` 就把攻击者数据写进 `ivi_server` 与 DBus daemon 之间已认证的 Unix socket。
- 该原语不需要泄露 PIE/libc，也不需要劫持控制流：它滥用的是程序自己的内部连接和协议状态。
- 通用模式：有符号/无符号混用 + 只做单边边界检查 + 数组索引按元素大小缩放。即使索引值看起来巨大/为负，缩放后的低位仍可能落在目标字段上；攻击者可根据结构体布局构造 `idx`。

## 触发条件

- 目标进程把外部可控整数作为数组下标，且只检查上界或只检查下界。
- 索引在机器码中按元素大小缩放（`idx * sizeof(element)`），高位可在 64 位地址计算中回绕。
- 目标字段（fd、函数指针、长度、标志）紧邻数组，且偏移是元素大小的整数倍。
- 目标进程已打开有价值的内部 fd/句柄，且后续对选中 fd 执行写/读/ioctl。
- 攻击者能向该接口发送请求并控制整数字段。

## 利用步骤

1. 逆向目标结构体布局，确认 `conn_fds` 数组长度、元素大小、相邻字段（如 `dbus_sock_fd`）的偏移。
2. 计算目标下标：`target_offset / sizeof(element)`；若正常值被上界检查拦截，寻找 `idx` 使 `(uint64_t)idx * sizeof(element) mod 2^64 == target_offset` 且有符号解释为负数（或反之绕过下界检查）。
3. 对 4 字节 `int` 数组，`idx = (1<<63) + target_index` 即可让有符号值为负、缩放后低位等于 `target_index*4`（示例 `0x800000000000000a` → 0x28）。
4. 通过协议发送 `conn_id = 该值`、`payload_len`、`payload`；确认目标 fd 收到数据（可用 DBus/内部协议响应验证）。
5. 把该写原语升级为内部协议调用：例如向已认证的 DBus socket 写一条裸 method call，触发高权限服务方法。
6. 若需要分块，利用 stream socket 无消息边界的特点，多次调用按顺序写同一 fd，接收端按协议长度字段重组。

## PoC

```c
// 目标检查：idx = (int64_t)conn_id; if (idx > 9) reject;
// 目标访问：target_fd = st->conn_fds[idx]; send(target_fd, frame, payload_len, 0);
uint64_t conn_id = 0x800000000000000aULL;  // 有符号为负，*4 回绕到 0x28
```

```python
import struct
# IVI 风格请求：magic, version, op, body_len, req_id
body = struct.pack("<Q", 0x800000000000000a) + struct.pack("<Q", len(payload)) + payload
req = struct.pack("<IIIII", 0x30495649, 1, 3, len(body), 0x5000) + body
sock.sendall(req)
```

PoC 未在本机执行；实际结构体布局、数组元素大小与内部 fd 用途需按目标调整。

## 变体与关联

- 变体：若检查是 `idx >= MAX` 但索引为 `uint32_t`，可用 `0x10000000a` 之类的值在缩放后回绕；关键是元素大小与目标偏移的整除关系。
- 变体：目标字段可能是函数指针数组、长度字段、引用计数；不一定是 fd。
- 变体：只检查 `idx < MAX` 而遗漏负数的模式也常见于 `int` 索引；`-1` 可命中数组前一个字段。
- 关联卡片：[[binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got]]（整数边界绕过导致堆利用）、[[binary-pwn-elf-copy-relocation-writable-security-state]]（邻接字段/安全状态改写）。
- 注意：本例为 Hackropole FCSC 2026 autodiag 题的自定义 IVI 服务；真实程序需具体审计符号混用与索引缩放。

## 检测与防御

- 防御：索引统一用无符号类型（`size_t`），同时检查 `idx >= count` 与 `idx < 0`（若保留有符号）；不要依赖单边检查。
- 防御：外部整数先做范围校验再转换；使用 `std::array`/`span`/边界检查容器；对 fd 数组使用句柄表 + cookie 而非裸下标。
- 防御：编译期开启 `-fsanitize=undefined,address` 与整数转换告警；代码审计关注 `int64_t idx = (int64_t)user_u64`、`arr[idx]`、`idx * sizeof`。
- 检测：请求中出现接近 `0x8000000000000000` 的索引值、超大/负的 id、数组下标异常；服务日志中 fd 访问越界；内部 IPC 收到非预期 method call。
- 响应：隔离服务、审计内部连接是否被注入、轮换相关凭据、修复边界检查。
