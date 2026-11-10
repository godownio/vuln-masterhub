---
id: defense-forensics-tinyshell-backdoor-traffic-decrypt
title: TinyShell 后门流量解密：40 字节 IV 握手 + SHA1(secret||IV) 派生 AES-128-CBC 会话密钥与 HMAC-SHA1 尾
type: scenario
domain: defense
path: defense/forensics
technique: tinyshell-traffic-decrypt-aes-cbc-sha1-iv
tags:
- forensics
- traffic-analysis
- tinyshell
- backdoor
- aes-cbc
- sha1
- hmac
- c2
- iot
- router
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V441
  verified_at: '2026-11-09T22:04:33+08:00'
  notes: 已对照原文核对：40 字节 IV1||IV2 握手、SHA1(secret||IV) 取 16 字节派生双向 AES-128 key、IV1/IV2 前 16 字节作初始 IV、challenge 5890ae86f1b91cf6298395711dde580d、2 字节大端长度 + 载荷补齐 16 字节、20 字节 HMAC-SHA1 尾，均与原文图29-33（pel_send_msg/pel_recv_msg 源码、IDA 与 pcap）一致；secret 默认 tinyshell 见图10/11；卡内 Python PoC 为按协议重写的等价实现（已审阅 CBC 逐块 IV 链式与跨消息延续逻辑正确）；未实测。
url: /docs/defense/forensics/defense-forensics-tinyshell-backdoor-traffic-decrypt/
draft: false
kb_aliases:
- TinyShell 解密
- tsh/tshd 通信分析
- Vault 7 TinyShell 协议
- secret tinyshell
- AES-CBC 链式 IV
- Wireshark C Arrays 批量解密
- 网络设备后门取证
---

## 一句话结论

TinyShell（`tsh`/`tshd`）建连时先明文发送 40 字节 `IV1||IV2`（各为 SHA1(时间, pid) 的 20 字节输出），随后双向各自用 `SHA1(内置 secret || IV)` 的前 16 字节作 AES-128 密钥、IV 的前 16 字节作 CBC 初始 IV，对“2 字节大端长度 + 载荷 + 零填充”的消息做 AES-CBC 加密并在每条消息后附 20 字节 HMAC-SHA1；只要抓到首个 40 字节握手包并知道 secret（开源版为 `tinyshell`），即可离线解出全部上行/下行命令与文件内容。

## 原理

- **握手**：连接建立后，客户端先调用 `gettimeofday`+`getpid` 做一次 SHA1 得到 IV1（20 字节），再对时间与 `pid+1` 做 SHA1 得到 IV2，把 `IV1||IV2` 共 40 字节明文发出。两端用同一对 IV 派生双向密钥。
- **密钥派生**：发送密钥 = `SHA1(secret + IV1)[:16]`，接收密钥 = `SHA1(secret + IV2)[:16]`；发送初始 IV = `IV1[:16]`，接收初始 IV = `IV2[:16]`。secret 编译在 `tsh.h` 的 `char *secret` 中，开源版为 `"tinyshell"`；CIA 的 TshPatcher 变体命令行带 passphrase，密钥材料可能不同。
- **消息格式**：每条消息先写 2 字节大端长度，再跟载荷，补齐到 16 字节整数倍；加密采用 AES-128-CBC，但链式状态跨消息连续——每个密文块都成为下一块的 IV（实现上等价标准 CBC，消息之间的 20 字节 HMAC 不参与链式状态）。密文之后附 20 字节 `HMAC-SHA1(64 字节密钥块 + 密文)`。
- **建连校验**：双方各自发送的第一条加密消息载荷是固定的 16 字节 challenge（十六进制 `5890ae86f1b91cf6298395711dde580d`）；解密后看到该常量即可确认密钥正确、方向正确。
- **为什么可离线解密**：IV1/IV2 是明文传输的，secret 是硬编码常量，AES 与 SHA1 都是标准算法；不需要破解任何密码学难题，只要拿到首个握手包并知道样本使用的 secret，就能复现全部会话密钥。HMAC 只用于完整性校验，解密不需要它。
- **方向判定**：首个 40 字节握手包由客户端（`tsh` 控制端）发往服务端（`tshd` 后门）；按五元组确定两端后，`tsh→tshd` 用 send 密钥/IV1，`tshd→tsh` 用 recv 密钥/IV2。

## 触发条件

- 已捕获 TinyShell 会话的完整 TCP 流（例如 Wireshark pcap），且包含连接建立后的首个 40 字节握手包。
- 知道目标样本的内置 secret：开源版默认 `tinyshell`；CIA 变体需从样本/命令行 passphrase 确认。
- 能按 TCP 流重组双向数据（Wireshark Follow TCP Stream 导出 C Arrays 或原始字节即可）。

## 利用步骤

1. 在 pcap 中定位 `tsh` 与 `tshd` 的会话，取连接建立后第一个由客户端发出的 40 字节数据，按 20/20 拆成 IV1、IV2。
2. 计算：`send_key = SHA1(secret||IV1)[:16]`、`recv_key = SHA1(secret||IV2)[:16]`、`send_iv = IV1[:16]`、`recv_iv = IV2[:16]`。
3. 按方向逐条解密：每 16 字节一块做 AES-128-CBC（IV 初始为上面的值，之后每块用上一密文块），首块明文前 2 字节为大端长度，按长度取载荷，补齐块后跳过 20 字节 HMAC，再继续下一条；链式 IV 跨消息延续。
4. 用 challenge 常量 `5890ae86f1b91cf6298395711dde580d` 验证首条消息解密正确。
5. 汇总解密出的命令与输出（上传/下载的文件内容也包含在消息载荷中），还原攻击者操作时间线与失窃文件。
6. 若样本是 CIA 变体，先用 passphrase/样本中的 secret 重试；密钥不对时首条消息不会解出 challenge。

## PoC

```python
import hashlib
from Crypto.Cipher import AES

SECRET = b"tinyshell"          # 开源版 tsh.h 内置 secret；变体需替换

def derive(hs40: bytes):
    iv1, iv2 = hs40[:20], hs40[20:]
    return (hashlib.sha1(SECRET + iv1).digest()[:16], iv1[:16],
            hashlib.sha1(SECRET + iv2).digest()[:16], iv2[:16])

def decrypt_records(data: bytes, key: bytes, iv: bytes):
    out, i = [], 0
    while i + 16 <= len(data):
        prev, blk = iv, data[i:i+16]
        pt0 = AES.new(key, AES.MODE_CBC, prev).decrypt(blk)
        n = int.from_bytes(pt0[:2], "big")
        blk_len = ((2 + n + 15) // 16) * 16
        chunks, cur_prev, off = [pt0], blk, i + 16
        while off < i + blk_len:
            blk2 = data[off:off+16]
            chunks.append(AES.new(key, AES.MODE_CBC, cur_prev).decrypt(blk2))
            cur_prev, off = blk2, off + 16
        out.append(b"".join(chunks)[2:2+n])
        iv = cur_prev                 # CBC 状态跨消息延续
        i += blk_len + 20             # 跳过 20 字节 HMAC-SHA1
    return out

# hs40 = 首个 40 字节握手包；up/down 为按方向重组后的密文字节
# ks, ivs, kr, ivr = derive(hs40)
# print(decrypt_records(up, ks, ivs), decrypt_records(down, kr, ivr))
```

## 变体与关联

- 变体：CIA 使用的 TshPatcher 变体命令行包含 passphrase，secret 可能由 passphrase 派生或直接在样本中替换；解密前先核对样本字符串/命令行。
- 变体：静态编译与动态编译只影响二进制体积与符号，不改变协议；IDA 中可用 SHA1 常量/`aes_encrypt` 调用点定位通信函数。
- 变体：Wireshark 可用“Follow TCP Stream → Show data as C Arrays”导出，再按脚本批量解密；也可直接用 tshark 导出原始字节。
- 关联：[[iot-mikrotik-chimay-red-stackclash-tinyshell-upload]]（该后门的植入链）、[[defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt]]（同类“从流量素材派生密钥后解密”的取证方法）、[[defense-forensics-adaptixc2-beacon-http-rc4-session-key-traffic-decrypt]]（C2 会话密钥还原）。
- 边界：丢失握手包或缺少 secret 时无法解密；只抓中间流、没有连接建立阶段时需依赖已知 IV（不可能，除非另有密钥材料）；HMAC 未校验不影响明文恢复。

## 检测与防御

- 检测：TinyShell 建连首包固定 40 字节且内容为两段高熵 SHA1 输出，随后立即进入 AES 密文流；默认服务端口 7586（`SERVER_PORT`），反连模式由路由器主动外联。可对“首包 40 字节 + 双向加密流 + 固定 challenge（解密后）”做协议指纹。
- 响应：用上述脚本解密 pcap 还原攻击者命令与文件传输，评估失窃配置/凭据；结合设备上的 `/ram` 文件、进程与出站连接判断是否仍在线。
- 修复：升级 RouterOS，关闭 WAN 侧管理端口，限制路由器出站；对网络设备做配置备份与完整性核查，重启清除内存后门并排查持久化脚本。
