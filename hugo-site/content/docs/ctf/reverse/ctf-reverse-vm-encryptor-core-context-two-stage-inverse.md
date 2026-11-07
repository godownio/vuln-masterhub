---
id: ctf-reverse-vm-encryptor-core-context-two-stage-inverse
title: VM 加密器逆向：core dump 恢复运行时上下文 + 两阶段 VM 变换逆序求逆
type: scenario
domain: ctf
path: ctf/reverse
technique: vm-encryptor-core-context-two-stage-inverse
tags:
- reverse
- vm
- core-dump
- cryptography
- ransomware
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:08:56+08:00'
  notes: 已对照原文 SigFlow 段核对：SIGLCK1 32 字节头、0x158 上下文、seed=ctx[0x148+i]^((i*0x37)&0xff)^nonce[i&7]、三段 pass 与逆序求逆、FNV-1a 校验、token 均一致；第一阶段小 VM key 流未实现（卡片已注明）；PoC 未本机复跑。
url: /docs/ctf/reverse/ctf-reverse-vm-encryptor-core-context-two-stage-inverse/
draft: false
kb_aliases:
- SigFlow 逆向
- VM 加密器求逆
- core dump 恢复上下文
- 两阶段 VM 变换
- .siglocked 解密
- 勒索加密器逆向
---

## 一句话结论

面对一个 strip 后静态链接、用两阶段字节 VM 加密文件的程序，可以先让原始程序处理小文件并在关键点触发 `SIGILL` 生成 core，从 core 中按内嵌 token 定位并提取运行时上下文（VM 表、seed、incident id），再按 opcode 逆向两个变换并“逆序”求逆（先逆 pass 3，再逆 pass 2/1），即可批量解密 `.siglocked` 文件。

## 原理

- 程序把内嵌 token（如 `SIGFLOW_RANSIM_TOKEN_2026_LOCKER`）与常量混合，初始化一块约 `0x158` 字节的上下文；上下文含 incident id、第二阶段的 32 字节 VM 表、16 字节 seed 材料。直接修改二进制会改变上下文，所以要在原始程序运行时取内存。
- 文件头是固定 32 字节：magic（8）、per-file nonce（8）、incident id（8）、明文长度（4，小端）、FNV-1a 32 校验（4），之后是密文。校验和用于验证解密结果。
- 第一阶段是“按字节生成 16 条指令的小 VM”：根据相对路径的 FNV-1a 哈希、per-file nonce、上下文表字节和滚动 32 位状态，为每个字节生成一个 XOR key；加密和解密都是再次 XOR 同一个 key。
- 第二阶段是字节级 VM，最终可化简为三段 pass：
  1. 前向：`r0=buf[0]`，从 `pos=1` 到 `n-1`，`r0=rol8(r0,(seed[pos&0xf]+1)&7)`，`buf[pos]^=r0`；
  2. 后向：`r0=buf[n-1]`，从 `pos=n-2` 到 `0`，`r0=rol8(r0,(seed[(pos+9)&0xf]+1)&7)`，`buf[pos]^=r0`；
  3. 逐字节表混合：`r0=seed[0]`，`r2=table[(pos+r0)&0x1f]`，`buf[pos]=((buf[pos]^r2)+r0)&0xff`。
- 求逆必须按相反顺序：先逆 pass 3（减 `r0` 再 XOR `r2`），再逆 pass 2（同样的滚动 XOR），最后逆 pass 1。因为 pass 1/2 不修改各自起始位置的字节，滚动状态可以从当前 buf 重新得到。
- seed 由上下文与 nonce 派生：`seed[i] = ctx[0x148+i] ^ ((i*0x37)&0xff) ^ nonce[i&7]`（i=0..15）。
- 为什么用 core：静态 strip 程序难以直接读全局；在原始进程执行到上下文初始化之后发送 `SIGILL`，core 会保存整块内存；用内嵌 token 搜索即可定位上下文，避免猜测偏移。

## 触发条件

- 目标为 strip/静态链接的加密器，存在内嵌 token/魔数、固定文件头、per-file nonce 与校验和。
- 能运行原始二进制（或已获得同版本样本）并使其崩溃生成 core（`ulimit -c unlimited`、`gcore`、`/proc/<pid>/mem` 均可）。
- 能逆向出两阶段变换的 opcode/表结构；或能从 core 中直接提取上下文与表。
- 加密文件保留原始相对路径（路径参与哈希），且校验和可验证。

## 利用步骤

1. 用 `file`/`checksec` 确认静态、strip；定位 `main`、上下文初始化、加密目录遍历、校验函数。
2. 解析 `.siglocked` 头：magic、nonce、incident id、明文长度、FNV-1a 校验；确认密文偏移 0x20。
3. 在原始程序上运行大量小文件，待上下文初始化完成后发送 `SIGILL` 生成 core；在 core 中搜索内嵌 token，提取 `0x158` 上下文（incident id、VM 表、seed 材料）。
4. 反汇编第一阶段 wrapper 与第二阶段 VM，记录 opcode 语义；把第二阶段化简为三段 pass，并写出逆变换。
5. 按 `seed` 公式和 per-file nonce 生成 seed；用原始相对路径（去掉 `.siglocked`）计算路径哈希，供第一阶段 key 流使用。
6. 对每个文件：读头 → 逆第二阶段（pass 3→2→1）→ 逆第一阶段 XOR → 校验 FNV-1a 与长度 → 写出明文。
7. 用校验和/文件类型验证结果；若失败，检查路径是否带前缀、nonce 字节序、表偏移或 pass 顺序。

## PoC

```python
def rol8(x, n):
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xff if n else x & 0xff

def seed_from(ctx, nonce):
    return bytes((ctx[0x148 + i] ^ ((i * 0x37) & 0xff) ^ nonce[i & 7]) & 0xff
                 for i in range(16))

def inv_stage2(buf, seed, table):
    n = len(buf)
    # inverse pass 3
    r0 = seed[0]
    for pos in range(n):
        r2 = table[(pos + r0) & 0x1f]
        buf[pos] = ((buf[pos] - r0) & 0xff) ^ r2
    # inverse pass 2
    r0 = buf[n - 1]
    for pos in range(n - 2, -1, -1):
        r0 = rol8(r0, (seed[(pos + 9) & 0xf] + 1) & 7)
        buf[pos] ^= r0
    # inverse pass 1
    r0 = buf[0]
    for pos in range(1, n):
        r0 = rol8(r0, (seed[pos & 0xf] + 1) & 7)
        buf[pos] ^= r0
    return buf
```

```text
# 文件头（小端）
0x00 8  magic "SIGLCK1\0"
0x08 8  per-file nonce
0x10 8  incident id
0x18 4  plaintext length
0x1c 4  FNV-1a 32 checksum
0x20 N  ciphertext
```

说明：PoC 为原文解密脚本的结构化精简，未在本机执行；第一阶段 key 流需按目标二进制的小 VM opcode 另行实现。

## 变体与关联

- 变体（取上下文）：`gcore`/`/proc/<pid>/mem`/调试器 dump 可替代 SIGILL core；若程序有反调试，可在初始化后 attach 或 patch 副本（注意 patch 会改变上下文）。
- 变体（变换）：多段 XOR/rol/表混合、按路径/时间/nonce 派生 key；逆变换顺序始终与加密相反。
- 变体（文件头）：nonce/长度/校验的字节序、magic 长度、校验算法（FNV/CRC/哈希）需按样本调整。
- 关联：[[ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse]]（UPX + 自定义 VM 求逆）；[[ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution]]（自修改 VM 字节码）；[[defense-forensics-core-dump-secret-extraction]]（core dump 敏感信息提取）。
- 边界：上下文每次运行随机、无 core/内存读取权限、路径哈希含未知前缀、或 VM 依赖外部状态时，需补充材料或改用动态调试。

## 检测与防御

- 检测：静态 strip 二进制中出现内嵌 token、固定 magic、`/proc/self`/anti-debug 检查、目录遍历加密与 restore note；文件被批量改名为固定后缀。
- 防御：不要用自研 VM/XOR 作为加密方案；使用标准 AEAD（AES-GCM/ChaCha20-Poly1305）与 KDF；密钥放 HSM/DPAPI/Keychain，不内嵌在二进制。
- 加固：加密器进程禁止 core dump（`RLIMIT_CORE=0`）、启用反调试与完整性校验；但这只是提高逆向成本，不能替代标准密码学。
- 取证：core dump 与内存镜像可作为证据提取上下文；保留原始样本与加密文件，按相对路径与校验和验证解密结果。
