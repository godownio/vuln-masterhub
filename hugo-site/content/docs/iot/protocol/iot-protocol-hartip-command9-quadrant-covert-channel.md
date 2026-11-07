---
id: iot-protocol-hartip-command9-quadrant-covert-channel
title: HART-IP Command 9 状态字段高两位隐蔽信道：四元符号 + 设备身份派生 XTEA 密钥的外传
type: scenario
domain: iot
path: iot/protocol
technique: hartip-command9-quadrant-covert-channel
tags:
- ics
- hart-ip
- covert-channel
- exfiltration
- command-9
- quaternary-encoding
- xtea
- cbc
- device-identity
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:18+08:00'
  notes: 对照工控231：cmd9 71 字节、8 个高两位符号、32 帧序列号 20480-20511、身份 18a42f39c0717d12b8、XTEA-CBC 一致；未复跑
url: /docs/iot/protocol/iot-protocol-hartip-command9-quadrant-covert-channel/
draft: false
kb_aliases:
- HART-IP 隐蔽信道
- Command 9 高两位四元编码
- 变送器数据外传
- 短地址 1 2 3
- XTEA-CBC 密钥派生
- 污染回声
---

## 一句话结论

被植入外传逻辑的 HART-IP 网关把三台变送器 Command 9 响应中本应为 0 的 8 个字节高两位当作四元符号，32 帧拼出 64 字节密文；设备身份按短地址顺序取命令 0 响应末 3 字节拼接后 SHA-256 派生 128 位 XTEA 密钥，CBC 解密后得到 flag 与 CRC32，形成一条混在正常轮询中的低带宽隐蔽信道。

## 原理

- **载体字段**：HART Command 9（读带状态的设备变量）的响应数据区固定 71 字节，偏移 10、18、26、…、66（步长 8）是变量状态字节，正常帧的这 8 个字节高两位恒为 0。被污染的帧把高两位用作四元符号：`0x00`→0、`0x40`→1、`0x80`→2、`0xC0`→3；每帧 8 个符号 = 16 位 = 2 字节，32 帧共 256 个符号 = 512 位 = 64 字节。
- **污染帧判定**：命令号 9、数据区长 71、短地址属于 {1,2,3}、至少一个状态字节高两位非零。正常轮询、重传和损坏帧会被过滤掉；原文从 8556 个 UDP 报文中筛出序列号 20480–20511 的 32 帧，按短地址交错、按序列号排序后拼符号。
- **密钥派生陷阱**：设备身份来自 Command 0 响应的 18 字节数据区。三台设备只有第 9 字节（等于各自短地址）和末 3 字节不同；HART 标准的唯一标识（扩展设备类型 + 设备 ID）三台完全相同，误用它派生密钥必错。真正用作身份的是末 3 字节：地址 1=18a42f、地址 2=39c071、地址 3=7d12b8，按地址顺序拼成 9 字节 `18a42f39c0717d12b8`，SHA-256 取前 16 字节得到 XTEA 密钥 `72ca6dade8c6207f5386f3b0a6c2dd20`。
- **加密格式**：64 字节密文前 8 字节为 CBC 初始向量，余 56 字节为 7 个分组。XTEA 使用 delta `0x9E3779B9`、32 轮、4 个 32 位大端字密钥；解密后去 PKCS5 填充。明文封装为 2 字节大端长度 `0x002a`=42、42 字节 flag、4 字节大端 CRC32（现算 `1c3a3c57` 与帧尾一致）。
- **为什么隐蔽**：外传发生在合法 Command 9 响应的“保留/状态”位里，不新增报文、不改协议结构，流量看起来只是正常轮询；只有把高两位聚合成符号并知道派生方式才能还原。带宽约 16 bit/帧，适合少量敏感数据外带。

## 触发条件

- 攻击者能控制/植入 HART-IP 网关或变送器的响应生成逻辑（固件植入、中间人篡改）。
- 目标网络允许 HART-IP（UDP 5094）轮询，且监控只检查命令号/长度/源地址，不校验状态字节高两位。
- 三台设备可被选中且短地址已知；攻击者能从 Command 0 响应中获取设备身份末 3 字节。
- 接收方知道密钥派生方式，才能解密外传数据。

## 利用步骤

1. 抓取 HART-IP 流量，按命令号统计；确认 Command 9 数量最大且响应长度 71，候选载体。
2. 过滤 cmd=9、len=71、短地址∈{1,2,3}、状态字节高两位非零的帧，记录序列号与符号。
3. 按序列号排序，把每帧 8 个符号按大端拼成 16 位/2 字节，得到 64 字节密文。
4. 从 Command 0 响应中取每台设备末 3 字节，按短地址顺序拼接 9 字节，SHA-256 取前 16 字节作为 XTEA 密钥。
5. 取密文前 8 字节为 IV，余下按 8 字节分组做 XTEA-CBC 解密，去 PKCS5 填充。
6. 解析 2 字节长度、flag 与 CRC32，校验 CRC 与帧尾一致。

## PoC

```python
import hashlib, struct, zlib

# 1) 从抓包筛污染帧：cmd=9, len=71, addr in {1,2,3}, 高两位非零
by_seq = {}
for seq, addr, cmd, d in frames:
    if cmd == 9 and len(d) == 71 and addr in (1, 2, 3):
        syms = [d[10 + 8 * i] >> 6 for i in range(8)]
        if any(syms):
            by_seq[seq] = syms

symbols = [s for k in sorted(by_seq) for s in by_seq[k]]
bits = "".join(format(x, "02b") for x in symbols)
ct = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8))

# 2) 设备身份：Command 0 响应末 3 字节，按短地址顺序拼接
identity = b"".join(ident[a] for a in (1, 2, 3))   # 18a42f 39c071 7d12b8
key = list(struct.unpack(">4I", hashlib.sha256(identity).digest()[:16]))

# 3) XTEA-CBC 解密（delta=0x9E3779B9, 32 rounds），IV=ct[:8]
iv, body = ct[:8], ct[8:]
pt = xtea_cbc_decrypt(body, key, iv)
pt = unpad_pkcs5(pt)
length = struct.unpack(">H", pt[:2])[0]
flag, crc = pt[2:2+length], struct.unpack(">I", pt[2+length:6+length])[0]
print(flag, hex(crc))
```

```text
# 符号映射
0x00 -> 0   0x40 -> 1   0x80 -> 2   0xC0 -> 3
# 32 帧 × 8 符号 × 2 bit = 512 bit = 64 B
```

## 变体与关联

- 变体：载体可换成其他保留位/状态位/时间戳低位、Command 1/3 的未用字段；四元符号可扩展为八元（3 位）或按位拆分。
- 变体：密钥派生可换成设备序列号、扩展设备类型、标签位图或固定常量；加密可换成 AES/XTEA/流密码。
- 关联：[[iot-protocol-someip-sd-stopoffer-spoof-tp-command]]（工控协议字段滥用与伪造）、[[web-generic-sqli-dnslog-oob-exfiltration]]（隐蔽外传思路）。
- 边界：需要能篡改响应生成逻辑或中间人；重传/损坏帧会破坏序列号与符号顺序，需按序列号去重；设备身份字段选择错误会导致密钥错误。

## 检测与防御

- 检测：Command 9 响应状态字节高两位非零、固定短地址集合的规律性帧、同一序列号区间内地址交错；对比设备固件/配置完整性；对 HART-IP 做深度包检测，统计每台设备的响应字段分布。
- 修复：网关/变送器固件签名与安全启动；HART-IP 网关只允许合法主站与命令白名单；对 Command 9 状态字段做规范化（清零未用高两位）并校验。
- 加固：网络分段与单向网关；监控异常外传带宽与固定周期；设备身份与密钥存放在安全元件；定期审计固件与配置。
