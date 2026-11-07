---
id: ctf-pwn-heap-residual-uninitialized-read-flag
title: 堆残留取 flag：启动时 flag 读入堆后 free，按 size class 重新申请并读未初始化内存
type: scenario
domain: ctf
path: ctf/pwn
technique: heap-residual-uninitialized-read-flag
tags:
- pwn
- heap
- uninitialized-read
- use-after-free
- tcache
- size-class
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:48:32+08:00'
  notes: 已对照原文 Heap Smash v1 核对：启动时 flag 读堆后 free、tcache 元数据占前 0x10、request2size 73-88 映射 0x60 chunk、1-72 为更小 chunk、89+ 为 0x70、A <idx> <size>/R <idx> 命令、73 起始可见 [16B metadata]+athena{...} 均一致；原文有实测 flag，未本机复跑。
url: /docs/ctf/pwn/ctf-pwn-heap-residual-uninitialized-read-flag/
draft: false
kb_aliases:
- Heap Smash v1
- 堆残留读 flag
- 未初始化堆读
- tcache 元数据后的残留数据
- size class 复用
---

## 一句话结论

服务启动时把 flag 读到堆上再 `free`，释放只把 tcache 链表指针和 key 写进用户区前 0x10 字节，后面的 flag 内容仍留在原 chunk；攻击者按相同 size class 重新 `malloc` 一块同尺寸内存（本题请求 73–88 字节都落在 0x60 chunk），程序未清零就直接 `read`，即可从 0x10 偏移之后读出残留的 flag。

## 原理

- **数据残留**：`free` 不会清零用户数据，只在该 chunk 的用户区开头写入 tcache `next`（以及 safe-linking 后的编码值）和 `key`，通常占前 0x10 字节；其余字节保持原样。
- **size class 复用**：glibc 的 `request2size` 会把请求大小向上对齐到 chunk size。请求 73 字节时 `(73+8+15)&~15 = 0x60`，用户可用 0x58=88 字节；因此请求 73–88 都会拿到 0x60 chunk，正好复用 flag 所在 chunk。
- **未初始化读**：note 分配后没有 `memset`，直接允许 `R` 读取；读取长度覆盖残留区域，就能把 flag 带出。
- **为什么小 size 读不到**：请求 1–72 映射到更小的 chunk（0x20–0x50），不会复用 flag 所在的 0x60 chunk，读到的是其他块的零/元数据；请求 89 以上映射到 0x70，同样错过。
- **为什么前 16 字节不是 flag**：tcache 元数据覆盖了用户区开头；flag 从偏移 0x10 开始出现，脚本里按正则搜索即可。

## 触发条件

- 服务启动时把敏感数据（flag/密钥）读入堆缓冲区，随后 `free` 但未清零。
- 攻击者可控制后续 `malloc` 的请求大小，并能读取未初始化内存（`read`/`write` 输出）。
- 目标 chunk 未被其他分配复用/覆盖，或复用后仍保留足够长的敏感数据。
- 了解 glibc size class 映射，能选到与 flag chunk 相同的请求大小。

## 利用步骤

1. 按题目描述确认 flag 在启动时被读入堆并 free。
2. 用不同请求大小扫描：从 1 开始递增，观察 `R` 返回内容何时出现非零数据。
3. 找到边界（本题 73）：请求 73–88 复用 0x60 chunk，返回前 0x10 字节 tcache 元数据 + 后续 flag。
4. 用该大小 `A 0 73` 分配 note，再 `R 0` 读取；按 `athena{...}` 或通用 flag 正则提取。
5. 若 flag 被截断，调整请求大小到该 size class 的最大可用值（0x58），或多次分配/读取。
6. 若目标 chunk 已被其他分配覆盖，尝试在服务刚启动、尚未进行其他堆操作时立即申请。

## PoC

```python
import re, socket

SIZE = 73
with socket.create_connection((HOST, PORT), timeout=5) as sock:
    sock.settimeout(5)
    sock.recv(4096)
    sock.sendall(f"A 0 {SIZE}\n".encode())
    sock.recv(4096)
    sock.sendall(b"R 0\n")
    data = sock.recv(4096)

flag = re.search(rb"athena\{[^}\n]+\}", data).group(0)
print(flag.decode())
```

原文回显结构：

```text
[16 bytes tcache metadata] athena{Tvqi1VFPpL0axzLj} ...
```

未在本机复跑。

## 变体与关联

- **size class 变体**：不同 glibc 版本的 `request2size` 对齐略有差异；用二分/扫描找边界，不要写死 73。
- **数据源变体**：flag 在栈上则需栈泄漏 + 栈扫描（见同批 Classy who? 卡）；在全局变量则需任意读/格式化输出。
- **覆盖变体**：若 flag chunk 被其他分配覆盖，可尝试在 free 后立即申请，或利用 tcache LIFO 顺序先取目标块。
- **关联**：[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（UAF 读堆/泄露）、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（tcache 元数据布局）；本卡强调“残留数据 + size class 命中”。

## 检测与防御

- 敏感数据使用后立即清零（`memset_s`/`explicit_bzero`），不要依赖 `free` 清除。
- 分配器返回的内存在使用前清零；避免把 flag 读入长期堆缓冲区。
- 限制服务的任意 size 分配与未初始化读接口；对 `R` 输出做长度/内容校验。
- 检测：服务启动后堆中出现 flag 明文、后续小尺寸分配返回非零残留、`R` 输出包含敏感格式串。
