---
id: ctf-forensics-reversed-7z-steghide-timestamp-squared-dynamic-key
title: 流量包尾部逆序 7z + steghide 密钥 + 时间戳平方动态 KEY 逐层解出 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: reversed-7z-steghide-timestamp-squared-dynamic-key
aliases:
- 逆序 7z 流量取证
- steghide 提取密钥
- 时间戳平方动态 KEY
- 多重移位解密
- pcap 尾部压缩包
tags:
- ctf
- forensics
- pcap
- 7z
- steghide
- timestamp
- dynamic-key
- multi-shift
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:20+08:00'
  notes: 已对照原文与全部 89 张图片核对；逆序 7z、steghide、动态 KEY 脚本一致；未在本机复现
---

## 一句话结论

从 pcap 跟踪 TCP 流发现数据以 `z7` 结尾，逆序后是 7z 压缩包；包内 `hide.jpg` 与 `解密器.c`；用 steghide 从 jpg 提取密钥；逆向 C 代码得知 KEY = `(timestamp^2 的后 16 位重复 4 次) XOR 固定 64 字节表`，再按 `[3,5,2]` 轮换位移；在中心时间戳 ±1 小时窗口内爆破，匹配目标串前 32 字符得到动态 KEY，最后用 KEY 运行 flag 生成器得到 flag。

## 原理

- **逆序 7z**：7z 文件以 `37 7A BC AF 27 1C`（`7z¼¯'`）开头，流量/文本中若出现结尾 `z7`，很可能是整个文件被逆序传输或存储；逆序后得到合法 7z。
- **steghide**：JPEG 可用 steghide 嵌入/提取数据，提取需要口令；口令可能藏在压缩包内的另一个文件或源码中。
- **动态 KEY**：解密器把时间戳 `v10` 平方，`snprintf(..., "%lld", v10*v10)` 取十进制字符串；取后 16 位重复 4 次得到 64 字节，再与固定 64 字节表 `BYTE_B60` 逐字节 XOR，得到 KEY。
- **多重移位**：生成器对 KEY 前 32 字符按位置轮换位移 `[3,5,2]`（字母表 26），得到目标串；逆过程即对每个字符按同样位移反向移动。
- **时间爆破**：题目给出中心时间戳（如 1625131800，对应 2021-07-01 17:30 UTC+8），在其前后 3600 秒窗口内枚举时间戳，计算动态 KEY、解密前 32 字符并与目标匹配；命中后得到完整 KEY，输入 flag 生成器解密。

## 触发条件

- 有 pcap/流量文本，TCP 流尾部出现异常 `z7` 或可逆序的压缩包数据。
- 压缩包内有图片与逆向程序/源码；图片可被 steghide 识别。
- 有时间相关的密钥生成逻辑与中心时间提示；目标输出可用于匹配。

## 利用步骤

1. 在 Wireshark 中 Follow TCP Stream，观察数据尾部为 `z7`；导出原始字节并逆序，保存为 `.7z`。
2. 解压得到 `hide.jpg`、`解密器.c` 等文件。
3. 用 steghide 对 jpg 执行 `steghide extract -sf hide.jpg`（口令从题目/源码/其他文件获取），得到密钥字符串。
4. 逆向 `解密器.c`：确认 KEY 生成方式（时间戳平方、后 16 位重复、XOR 固定表）与多重移位规则。
5. 写脚本在中心时间戳 ±3600 秒内枚举，计算 KEY 并解密前 32 字符，匹配目标串；命中时间戳即得到 KEY。
6. 用 KEY 运行/解密 flag 生成器，得到 flag。

## PoC

动态 KEY 与时间爆破（Python）：

```python
import datetime

CENTER_EPOCH = 1625131800
SEARCH_WINDOW = 3600
TARGET = "lzonc2550f12s3964f5spqornmzjfgg7"
BYTE_B60 = [0x5E,0x55,0x44,0x42,0x5C,0x07,0x04,0x0D,0x07,0x51,0x01,0x0B,
            0x42,0x01,0x0E,0x00,0x05,0x58,0x00,0x4B,0x46,0x41,0x45,0x4C,
            0x46,0x4A,0x52,0x54,0x5F,0x5B,0x5D,0x01,0x76,0x76,0x60,0x75,
            0x6D,0x7D,0x4A,0x57,0x5C,0x49,0x53,0x09,0x07,0x07,0x04,0x55,
            0x5E,0x40,0x41,0x46,0x40,0x59,0x53,0x48,0x02,0x01,0x09,0x0E,
            0x02,0x50,0x05,0x4B,0x00]

def gen_key(ts):
    s = str(ts * ts)
    s16 = s[-16:] if len(s) > 15 else s.zfill(16)
    return ''.join(chr((s16 * 4).encode()[i] ^ BYTE_B60[i]) for i in range(64))

def unshift(text):
    shifts = [3, 5, 2]
    out = []
    for i, ch in enumerate(text):
        if ch.isalpha():
            base = ord('a') if ch.islower() else ord('A')
            out.append(chr((ord(ch) - base - shifts[i % 3]) % 26 + base))
        else:
            out.append(ch)
    return ''.join(out)

for ts in range(CENTER_EPOCH - SEARCH_WINDOW, CENTER_EPOCH + SEARCH_WINDOW + 1):
    key = gen_key(ts)
    if unshift(key[:32]) == TARGET:
        print(ts, datetime.datetime.utcfromtimestamp(ts), key)
        break
```

## 变体与关联

- 逆序/倒置的压缩包可换成逆序 ZIP、XOR 头、base64 包裹；先看文件头/尾魔数。
- steghide 口令来源：源码硬编码、图片元数据、流量中的其他字段、字典爆破。
- 动态 KEY 可换成时间戳、随机种子、机器 ID；核心是“找到可枚举的种子并在小窗口内匹配已知明文”。
- 关联：pcap 中隐藏压缩包、图片隐写、时间种子密钥逆向。

## 检测与防御

- 流量审计关注 TCP 流尾部的异常魔数/逆序数据；对导出的文件做 binwalk/foremost 与文件头校验。
- 对图片做 steghide/隐写检测；对二进制中的时间函数、平方/取模/固定表 XOR 做特征识别。
- 防御方应避免用时间戳等可枚举值派生密钥；使用 CSPRNG 与足够熵的密钥。
