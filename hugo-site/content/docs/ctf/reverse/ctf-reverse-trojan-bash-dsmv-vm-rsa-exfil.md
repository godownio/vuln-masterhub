---
id: ctf-reverse-trojan-bash-dsmv-vm-rsa-exfil
title: 投毒 bash 后门 DSMV 协议逆向：自定义帧 + VM 字节码 + RSA 块变换还原外带
type: scenario
domain: ctf
path: ctf/reverse
technique: trojan-bash-dsmv-vm-rsa-exfil
tags:
- reverse
- vm
- protocol
- rsa
- pcap
- trojan
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:09:00+08:00'
  notes: 已对照原文 evil_bash 段核对：DSMV 帧、type 1-5、4444 流去头后与本地 bash SHA-256 一致、type 2 用 e 还原/type 3 需 d、128→126 块变换、32 层 OpenSSL 口令均一致；已修正一句话结论中 type 2 密钥方向（原文 c^e mod n==m，服务端用私钥侧处理、可用 e 还原）；PoC 未本机复跑。
url: /docs/ctf/reverse/ctf-reverse-trojan-bash-dsmv-vm-rsa-exfil/
draft: false
kb_aliases:
- evil_bash 逆向
- DSMV 协议
- 投毒 bash 后门
- VM 字节码 popen
- RSA 块变换 128 126
- 32 层 OpenSSL 外带
---

## 一句话结论

被投毒的 bash 会在后门线程中连接 `127.0.0.1:9999`，用自定义 `DSMV` 帧（magic/type/length/payload/crc32）通信；握手下发 RSA `n|e`，type 2 是服务端下发、可用公钥指数 `e` 还原的 VM 字节码（含 `popen` 危险 opcode），type 3 是客户端回传结果。按协议拆包、解 VM 可还原攻击命令；再用 Wiener 攻击从异常大的 `e` 恢复 `d`，即可解密 type 3 外传包并还原 flag。

## 原理

- 后门逻辑在 `start_routine` 线程：初始化时解密出 `127.0.0.1`，连接 `9999`，然后循环收包、解包、执行 VM、回包。
- 协议帧固定：`magic "DSMV"`（4）| `type`（4）| `length`（4）| `payload`（length）| `crc32`（4）。类型：1 握手（RSA 参数）、2 服务端命令 VM、3 客户端结果、4 ack、5 close。
- 握手包 payload 是 `n|e` 两段十六进制。`type 2` 的 payload 用 `pow(c, e, n)` 解出 VM 字节码；`type 3` 的 payload 需要用私钥 `d` 才能解，说明客户端回包使用了另一侧密钥。
- RSA 块变换不是标准整段加密，而是按固定块做模幂：`sub_A87A0` 做 128→126 字节、`sub_A8950` 做 126→128 字节，内部是 `mpz_import → mpz_powm → mpz_export`。
- VM 由初始化、装载字节码、解释执行三部分组成；危险 opcode 直接调用 `popen(command, "r")`，因此控制端可以远程下发 shell 命令。
- 握手中的 `e` 异常大（接近 1024 位），而 `d` 很小，符合 Wiener 攻击场景；对 `(n,e)` 做连分数收敛即可恢复 `d`。
- 外带链：VM 命令把 `flag.txt` 打包成 `flag.tar`，连续 32 层 `openssl enc -aes-256-cbc -salt -pbkdf2` 加密，最后 `base64 flag.enc.32.tar` 通过 type 3 回传；拿到 32 个口令后逆序解密即可。

## 触发条件

- 有被投毒的 bash 二进制和对应 pcap；二进制包含后门线程、`DSMV` magic、VM 解释器。
- pcap 中有到 `127.0.0.1:9999` 的控制流，且包含握手、type 2/3 包。
- 能从二进制/握手中提取 `n,e`；type 3 需要 `d`（小私钥或可分解）。
- VM 命令与外带数据未被截断；OpenSSL 口令可从 VM 命令中还原。

## 利用步骤

1. 逆向 `main → start_routine`，确认连接地址/端口、`DSMV` 帧格式、收发函数与 VM 初始化/解释函数。
2. 用 tshark 跟随 TCP 流，区分“下发投毒 bash”的大流（如 4444）与“控制”流（9999）；对 4444 流去掉文件传输头后可与本地 bash 做 SHA-256 比对。
3. 在 9999 流中按 `DSMV` 拆包，提取 type 1 的 `n|e`。
4. 对 type 2 的 payload 按 128 字节块做 `pow(c, e, n)`，拼接得到 VM 字节码；实现/复用 VM 解释器，提取 `popen` 命令、目录列表、32 层 OpenSSL 口令。
5. 对 `(n,e)` 跑 Wiener 攻击恢复 `d`；对 type 3 的 payload 按 128 字节块做 `pow(c, d, n)`，拼接客户端回传数据。
6. 从回传数据中提取 `ls` 输出与 Base64（`U2FsdGVkX1...` 为 OpenSSL `Salted__`）；按 VM 命令中的 32 个口令逆序执行 `openssl enc -d -aes-256-cbc -salt -pbkdf2`，解包 `flag.tar` 得到 flag。
7. 校验 CRC32 与块长度；若 VM 解释失败，按 opcode 表逐条跟踪，注意跳转/循环与寄存器状态。

## PoC

```python
import struct

MAGIC = b"DSMV"

def parse_packets(data: bytes):
    out, i = [], 0
    while i + 16 <= len(data):
        if data[i:i+4] != MAGIC:
            i = data.find(MAGIC, i + 1)
            if i < 0: break
            continue
        typ, ln = struct.unpack_from(">II", data, i + 4)
        end = i + 12 + ln + 4
        if end > len(data): break
        out.append((typ, data[i+12:i+12+ln]))
        i = end
    return out

def rsa_blocks(payload: bytes, n: int, exp: int, in_block=128, out_block=126):
    res = bytearray()
    for off in range(0, len(payload), in_block):
        c = int.from_bytes(payload[off:off+in_block], "big")
        m = pow(c, exp, n)
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b""
        res.extend(b"\x00" * (out_block - len(raw)) + raw)
    return bytes(res)

# n, e = 从 type 1 的 "n|e" 解析
# vm_code = rsa_blocks(type2_payload, n, e)
# client   = rsa_blocks(type3_payload, n, d)   # d 由 Wiener 恢复
```

说明：PoC 为原文脚本的结构化精简，未在本机执行；VM 解释器与 32 层 OpenSSL 解密脚本较长，按 opcode/口令列表实现即可。

## 变体与关联

- 变体（协议）：magic/type/length/crc 的字节序、CRC 算法、类型编号可能不同；先按固定 magic 定位，再逐字段验证。
- 变体（RSA）：块大小可能为 128/256 字节，输出块比输入少 2 字节；若 `e` 正常而 `d` 未知，尝试分解 `n`、共模、小私钥等其他攻击。
- 变体（VM）：opcode 表、寄存器数量、跳转/循环语义不同；可用动态调试或符号执行辅助。
- 变体（外带）：多层 OpenSSL/AES、Base64/Base58、分片回传；按 VM 命令重建口令与顺序。
- 关联：[[crypto-rsa-wiener-small-private-exponent-large-e]]（本链的 RSA 小私钥攻击）；[[ctf-reverse-vm-encryptor-core-context-two-stage-inverse]]（另一类 VM 加密器逆向）；[[defense-forensics-behinder-php-webshell-traffic-decrypt]]（加密 WebShell 流量还原）。
- 边界：type 3 的 `d` 无法恢复、pcap 丢包/乱序、VM 依赖主机状态、或 OpenSSL 口令不完整时，只能还原部分链路。

## 检测与防御

- 检测：bash 二进制哈希/大小异常、出现 `DSMV` 字符串、`pthread_create` 后门线程、连接 `127.0.0.1:9999`；主机上出现异常 `popen` 子进程与 32 层 OpenSSL 临时文件。
- 防御：保护 bash 等系统二进制完整性（包管理器校验、AIDE/Tripwire）；限制本地回环异常端口通信；EDR 监控 `popen`/`execve` 链与大量 OpenSSL 调用。
- 加固：不要以 root 运行不可信脚本；对下载的二进制做签名校验；监控 `flag.tar`/`flag.enc.*` 等异常文件创建。
- 取证：保存 pcap、样本、VM 命令与外带文件；按 CRC/哈希验证还原结果，记录 32 层解密的口令顺序。
