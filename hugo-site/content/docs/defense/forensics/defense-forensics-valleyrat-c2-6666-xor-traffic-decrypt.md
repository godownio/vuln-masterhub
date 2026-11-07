---
id: defense-forensics-valleyrat-c2-6666-xor-traffic-decrypt
title: ValleyRAT C2 流量解密：6666/0x36 线索与载荷前缀多字节 XOR 密钥还原主机信息与登录模块插件
type: scenario
domain: defense
path: defense/forensics
technique: valleyrat-c2-6666-xor-traffic-decrypt
tags:
- forensics
- traffic-analysis
- valleyrat
- silverfox
- c2
- xor
- decrypt
- plugin
- pcap
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-06'
updated: '2026-11-06'
url: /docs/defense/forensics/defense-forensics-valleyrat-c2-6666-xor-traffic-decrypt/
draft: false
kb_aliases:
- 6666 XOR 解密
- 0x36 重复 XOR
- ValleyRAT 流量分析
- 银狐 C2 解密
- 登录模块.dll 提取
- CyberChef 多字节 XOR
- 重复密钥 XOR
- C2 payload 解密
---

## 一句话结论

在 ValleyRAT/银狐样本的沙箱抓包中，C2 载荷会出现大量连续的 `6666`/`0x36` 段；原文据此推测为 XOR 密钥并成功解密。但原文 CyberChef 截图显示实际 Key 是载荷前缀的多字节 HEX 周期串（可见 `2809de46…`、`ede463…`，其中含 `36 36 36 36`），并非固定 4 字节 ASCII `6666`。正确做法是先从载荷恢复重复密钥（前缀周期或已知明文），再用它 XOR 出主机信息、配置字段与 C2 下发的 `登录模块.dll`。

## 原理

- **`6666` 是“密钥含 0x36 + 明文为零”的乘积，不一定是完整密钥**：重复密钥 XOR 下，明文长串零字节（0x00）遇到密钥中的 `0x36` 字节会变成 ASCII `6`，所以密文会出现大量 `6666...`。这只能说明密钥中存在 `0x36` 字节，不能直接推出密钥就是 4 字节 `"6666"`。
- **截图中的实际密钥**：原文两张 CyberChef 截图的 XOR 算子均勾选 `HEX`，Key 分别以 `2809de46363636…` 和 `ede46363636…` 开头；对应载荷开头也按同一多字节周期重复。也就是说，真实密钥是每段载荷的重复块（可能取自载荷前缀），其中包含 `36 36 36 36`，因此肉眼看到大量 `6666`。以固定 `b"6666"` 去解，通常无法得到截图中的 `Windows`/`DESKTOP-`/`MZ` 结果。
- **如何恢复密钥**：若明文头部是零填充或固定头，密文前缀会直接重复出密钥；可用“最小周期”检测取 `cipher[:p]` 作为密钥。也可用已知明文（UTF-16LE 主机信息、PE 头 `MZ`/`PE`、配置字段）反推对应密钥字节，再扩展到整个周期。
- **XOR 自反**：加解密使用同一操作；`plain[i] = cipher[i] ^ key[i % len(key)]`。明文可能是 UTF-16LE 字符串、PE/DLL 或混合结构，解密后按字符串/文件头判断。
- **原文结果**：解密后得到样本上传信息（主机名、系统版本、配置等）以及 C2 下发的 `登录模块.dll` 插件内容；插件默认配置指向内网 `192.168.1.200:6669`，运行后按配置替换为真实 C2 `108.187.7.15:447` 等。
- **密钥强度与边界**：重复密钥 XOR 属弱加密；只要恢复周期或利用已知明文即可离线解密。不同 ValleyRAT/银狐变体可能更换密钥、改用 AES/滚动 XOR，不能把 `6666` 当作所有版本的通用密钥。

## 触发条件

- 捕获到 ValleyRAT/银狐系样本的 C2 TCP 流量（PCAP、沙箱网络日志、EDR 网络事件载荷），且载荷未被 TLS/额外封装。
- C2 载荷使用重复密钥 XOR；密文中可见大量 `6666`/`0x36` 连续段，或前缀呈明显周期重复。
- 能导出原始 TCP 载荷（Wireshark Follow TCP Stream → Raw），并有 CyberChef/Python 等工具。
- 明文可能是二进制（PE/DLL）、UTF-16LE 字符串或混合结构；需要按文件头/字符串判断。

## 利用步骤

1. 在 Wireshark 中过滤可疑 C2 会话（按 IP/端口或样本外联地址），Follow TCP Stream，导出 Raw 载荷；若一个流包含多段数据，按协议/长度切分。
2. 观察载荷中的重复模式：搜索 `6666`、`0x36` 连续段，记录候选密钥（ASCII `6666`、单字节 `0x36`、载荷前缀周期块）。
3. 先快速试 `b"6666"`/`b"6"`/`b"\x36"*4`；若解密结果不是 `Windows`/`DESKTOP-`/`MZ`，不要强行继续，改用周期检测。
4. 取载荷前缀的最小重复周期 `p`，以 `cipher[:p]` 作为重复密钥（或结合已知明文恢复密钥字节），再对整个载荷 XOR；CyberChef 中把该 HEX 串填入 XOR 的 Key（勾选 HEX）。
5. 检查解密结果：可读的主机名、Windows 版本、配置字段（`p1/o1` 等）、PE/DLL 头（`MZ`/`PE`）；若出现 `MZ`，按 PE 大小 carve 出插件。
6. 对提取的 `登录模块.dll` 计算哈希、查导入表/字符串、分析其配置（默认内网 C2 与真实 C2 替换逻辑）。
7. 对同一 C2 的其它会话重复“找周期/试候选 → XOR → 验证”，按时间线还原上线、插件下发与远控指令；将密钥/周期特征写入检测规则。

## PoC

Python 解密与提取（只读分析，未连接真实 C2）：

```python
from pwn import xor

cipher = open('c2_payload.bin', 'rb').read()

def looks_plain(out):
    head = out[:0x400]
    return b'Windows' in head or b'DESKTOP' in head or b'MZ' in head

plain = None
# 1) 先试常见 6666/0x36 候选；不要假定一定成功
for key in (b'6666', b'6', b'\x36\x36\x36\x36'):
    out = xor(cipher, key)
    if looks_plain(out):
        print('candidate key:', key)
        plain = out
        break

# 2) 候选失败：找前缀最小周期，把 cipher[:p] 当重复密钥
if plain is None:
    p = next((n for n in range(1, 65) if cipher[:n] == cipher[n:2*n]), None)
    if p:
        key = cipher[:p]
        print('period:', p, 'key:', key.hex())
        plain = xor(cipher, key)
        print('readable:', looks_plain(plain))

open('c2_payload.dec', 'wb').write(plain or b'')
# 若明文含 PE/DLL，按 MZ/PE 头 carve
i = (plain or b'').find(b'MZ')
if i != -1:
    open('login_module.dll', 'wb').write(plain[i:])
```

CyberChef 配方（等价操作）：

```text
From Hex → XOR (Key: 实际多字节 HEX 密钥或先试 6666；Scheme Standard) → To Hexdump
# 若 6666 解出乱码，把 XOR 的 Key 换成从载荷前缀恢复的 HEX 周期串
```

## 变体与关联

- 变体：部分会话的密钥确实是短密钥（`6666`/单字节 `0x36`）；另一些会话使用载荷前缀的多字节周期密钥，必须按实际抓包恢复。
- 变体：密钥可能由配置/主机信息派生；可用已知明文（全零填充、UTF-16 字符串、PE 头）反推。
- 变体：部分 ValleyRAT/Winos 变体使用 `(key+0x36)` 滚动 XOR、AES-GCM 或 zlib 压缩；遇到不可读结果时先确认算法，不要只试 `6666`。
- 变体：C2 载荷可能分帧（长度字段、指令字节），需先切帧再 XOR；插件可能经过压缩/二次加密。
- 关联：[[defense-forensics-winos4-c2-frame-xor-decrypt]]（Winos4 4 字节长度 + 10 字节密钥 + `+0x36` 滚动 XOR）、[[defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt]]（PyInstaller 木马 AES-GCM 帧）、[[defense-forensics-njrat-c2-traffic-base64-decode]]（NjRAT Base64 流量）、[[code-analysis-reverse-windows-valleyrat-staged-shellcode-codemark-reflective-pe]]（本样本完整加载链）。
- 边界：流量被 TLS 封装、密钥周期无法从载荷恢复、载荷经过压缩/二次加密、只有单向数据或抓包不完整时，需结合样本内存/配置进一步分析。

## 检测与防御

- **检测特征**：C2 载荷中出现大量连续 `6666`/`0x36`，且前缀存在多字节周期；对原始 TCP 载荷尝试“候选 6666 + 周期密钥”XOR 后出现 `MZ`/`PE`/UTF-16 主机信息。
- **网络侧**：对已知 ValleyRAT C2 IP/端口（如 `108.187.7.15:447/448`）告警；对原始 TCP 载荷做 XOR 试探与 PE carve；结合 JA3、域名、证书、User-Agent 做家族聚类。
- **主机侧**：监控 `HKCU\Console\0|1` 下 MD5 命名值、`%TEMP%\packer_temp_*`、UPX 子进程与反射 PE 内存；与流量告警联动。
- **防御**：对 C2 流量做 TLS/证书固定与出口过滤；EDR 拦截未签名外联与内存 PE；对沙箱/邮件网关增加“重复 6666/0x36 + PE 下载”规则。
- **响应**：解密流量还原攻击者操作与插件；提取 `登录模块.dll` 分析其 C2/指令；清理注册表插件与持久化，轮换凭据并升级检测规则。
