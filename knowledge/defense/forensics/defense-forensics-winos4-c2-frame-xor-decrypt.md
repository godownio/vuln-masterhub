---
id: defense-forensics-winos4-c2-frame-xor-decrypt
title: Winos4 C2 通信解密：4 字节长度 + 10 字节密钥 + 1 字节指令 + (key+0x36) 滚动 XOR
type: scenario
domain: defense
path: defense/forensics
technique: winos4-c2-frame-xor-decrypt
aliases:
- Winos4 通信解密
- Winos4 协议分析
- 4+10+1 帧
- key + 0x36 XOR
- 滚动 XOR 解密
- 银狐 Winos 流量
- Winos4 C2 decrypt
tags:
- forensics
- traffic-analysis
- windows
- winos4
- silverfox
- c2
- xor
- protocol
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:01:39+08:00'
  notes: 已对照 content.md、Go 解密脚本与图 09/30-35 核对：4 字节小端长度 + 10 字节密钥材料 + 1 字节指令 + (key+0x36) 10 字节滚动 XOR；FUN_decode 的 %0xA 索引重置与反编译一致；会话帧解密输出一致。未在本机复跑解密脚本、未连接真实 C2；变体加密方式仅原文背景提及。frontmatter 无 sources/source_url。
---

## 一句话结论

Winos4 各模块使用同一套自定义二进制帧：4 字节小端长度（含头部）+ 10 字节密钥材料 + 1 字节控制指令 + XOR 加密数据；密钥字节为 `密钥材料[i] + 0x36`（按 10 字节循环），用它对第 11 字节之后的数据逐字节 XOR 即可还原明文。按该格式解析 TCP 会话即可还原上线、下插件与远控指令流量。

## 原理

- **帧结构**：`[4 字节长度 L][10 字节密钥材料][1 字节指令][L-4-10-1 字节密文]`。长度字段为小端，包含 4 字节长度自身；接收端先读 4 字节得到 L，再读 `L-4` 字节，其中前 10 字节为密钥材料、第 11 字节为指令、其余为密文。
- **密钥派生**：反编译 `FUN_decode` 显示：取 `Src[a5] % 456`（`Src` 为字节，实际不超过 255，`%456` 近似无操作），加 `0x36` 得到密钥字节，与密文异或；每处理 10 字节把密钥索引重置为 0。因此密钥流是 10 字节密钥材料各加 `0x36` 后循环使用。
- **加解密对称**：`FUN_decode` 同时用于加密与解密（XOR 自反）。`上线模块.exe`、`登录模块.dll`、`文件管理.dll` 等所有模块都包含同一套 `FUN_decode`/`FUN_send` 函数，每个模块各自与控制端建立连接并使用相同协议。
- **指令字段**：第 11 字节是控制指令。登录模块中可见指令包括 0x00 加载插件、0x01 加载插件并写 `HKCU\Console\0\xxx`、0x02 关闭连接、0x03/0x04/0x0a/0xc9 屏幕/窗口信息、0x05 上传并执行文件、0x06 URL 下载执行、0x07 更新 REMARK/GROUP、0x08 查找进程、0x0b 清除日志、0x0c/0x0d 重启/终止自身、0x0e~0x10 注销/重启/关机、0x11 更新插件加载方式、0x12 更新配置并写 `IpDate`、0x13 新建外联、0x64/0x65 更新/删除 `IpDatespecial`、0xca 阻止系统休眠。
- **通信流程**：`上线模块` 上线后与控制端交互 4 段数据：控制端下发载荷 MD5、木马端回传信息、控制端下发插件内容等；每加载一个新插件，插件自身再与控制端建立独立连接并传输对应数据（文件管理传目录、查注册表传注册表信息等）。
- **家族差异**：Winos 系存在多种加密方式：仅 XOR、XOR+加法、Zlib 压缩、加法+异或+Zlib、AES；密钥可能从载荷中动态计算或固定。本文分析的是以帧内 10 字节密钥材料派生 XOR 密钥的早期版本，遇到其他变体需先确认加密方式。
- **为什么可解**：密钥材料随帧明文传输，且派生算法简单（+0x36、10 字节循环）；只要按长度字段正确切帧，不需要样本密钥即可离线还原全部会话。

## 触发条件

- 捕获到 Winos4 系木马的 TCP 会话流量（PCAP、代理日志、EDR 网络事件载荷），或从内存 dump 中提取到通信缓冲区。
- 流量是完整的二进制帧，未被 TLS/额外封装；若是 HTTPS 隧道需先解密。
- 已知或可推断帧格式（4 字节小端长度 + 10 字节密钥 + 1 字节指令）。
- 需要分析工具（Wireshark 导出原始 TCP 流、Python/Go 脚本、CyberChef）；明文可能包含 UTF-16LE 字符串。

## 利用步骤

1. **导出 TCP 流**：在 Wireshark 中对可疑会话 Follow TCP Stream，选择 Raw/原始数据导出；若一个会话包含多帧，按长度字段循环切分。
2. **解析帧头**：读前 4 字节小端得到 L；确认 `L >= 15`（4+10+1）；读取 `L-4` 字节作为帧体。
3. **取密钥与指令**：帧体前 10 字节为密钥材料，第 11 字节为指令；对密钥材料每个字节加 `0x36` 得到 10 字节 XOR 密钥。
4. **解密**：对帧体第 11 字节之后的密文逐字节与密钥 `i % 10` 异或；结果即明文。
5. **解析明文**：明文可能是 UTF-16LE 字符串（插件名、窗口标题、注册表路径）、PE 数据或二进制配置；用 CyberChef `From Hex` → `Decode text UTF-16LE` 或脚本处理。
6. **串联会话**：上线模块的 4 段交互、登录模块的窗口标题/插件下发、各插件自己的会话分别解密，按指令字段还原攻击者操作时间线。

## PoC

最小 Python 解密脚本（只读分析，未在本机执行）：

```python
import struct, sys

data = open(sys.argv[1], 'rb').read()
off = 0
while off + 4 <= len(data):
    L = struct.unpack('<I', data[off:off+4])[0]
    if L < 15 or off + L > len(data):
        break
    body = data[off+4:off+L]
    key = bytes((b + 0x36) & 0xff for b in body[:10])
    cmd = body[10]
    plain = bytes(c ^ key[i % 10] for i, c in enumerate(body[11:]))
    print(f'@{off:#x} len={L} cmd={cmd:#04x} plain={plain[:64]!r}')
    off += L
```

Go 版本核心逻辑（原文脚本）：`BytesToInt_Little(header)` 读长度 → `AddOneToEachByte(data[:10])` 得到 key → `MultiByteXOR(data[11:], key)`。

## 变体与关联

- 变体：仅 XOR（无 +0x36）、XOR+加法、Zlib 压缩、加法+异或+Zlib、AES；密钥固定或从载荷计算。遇到无法解出的帧，先检查前 10 字节是否真的是密钥材料，或协议是否已换成其他版本。
- 变体：每个插件独立连接，可能使用不同端口/主机；指令集可能随版本增删。
- 关联：[[defense-forensics-winos4-plugin-registry-residency-extraction]]（插件注册表驻留）、[[code-analysis-reverse-windows-winos4-builder-resource-config-injection]]（载荷生成与配置）、[[defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt]]（另一种长度前缀 C2 帧解密）。

## 检测与防御

- **流量检测**：识别“4 字节小端长度 + 10 字节高熵密钥 + 1 字节指令”的二进制帧；同一主机短时间内多个进程/模块连接同一 C2；明文解密后出现 `HKCU\Console`、插件名、窗口标题等特征。
- **主机检测**：结合注册表插件卡，检查 `Console\0/1`、`IpDate` 与模块加载行为；监控 `0x05/0x06` 上传执行、`0x0b` 清日志、`0x0e~0x10` 关机重启等高危指令对应的系统行为。
- **响应**：导出并解密会话还原 C2、插件与操作；封禁 C2；按注册表/文件清理；若流量为 TLS，需在端点侧获取明文或使用内存中的会话密钥。
- **加固**：限制出站到未知 IP/端口，启用网络分段与 EDR；对已知 Winos4 帧特征做 IDS 规则；定期狩猎 `HKCU\Console` 异常值。
