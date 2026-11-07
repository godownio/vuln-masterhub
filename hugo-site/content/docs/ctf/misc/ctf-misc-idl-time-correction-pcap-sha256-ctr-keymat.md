---
id: ctf-misc-idl-time-correction-pcap-sha256-ctr-keymat
title: 跨 IDL 时间修正穷举 + PCAP 密文重组 + SHA256-CTR KEYMAT 解密
type: scenario
domain: ctf
path: ctf/misc
technique: idl-time-correction-sha256-ctr-keymat
tags:
- ctf
- misc
- timezone
- idl
- pcap
- sha256
- ctr
- keymat
- xor
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:21:08+08:00'
  notes: 已对照原文核对：LX517.txt 末尾 Base64 提示 KEYMAT/ALGO:SHA256|XOR|CTR/REASM/IDRULE、EVT_A/B/C 时间锚点、经度估时区与 0/-1DAY 枚举、pcap 中 CIPH 密文、SHA256(keymat+BE32(counter)) 流异或、命中 ISCC{32hex} 与实测 keymat/flag 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/misc/ctf-misc-idl-time-correction-pcap-sha256-ctr-keymat/
draft: false
kb_aliases:
- 国际日期变更线时间修正
- DATE_CORR=-1DAY
- KEYMAT 模板
- SHA256 CTR XOR
- CIPH 密文
- 长虹守卫
---

## 一句话结论

日志末尾的 Base64 提示给出 `KEYMAT` 模板和 `SHA256|XOR|CTR` 算法；从事件行提取 TCP_SYN_SENT、IDL_CROSS、ANOMALY_MARKER_A2 三类本地时间，按经度猜时区并枚举 0/`-1DAY` 日期修正得到 UTC epoch 候选；pcap 的 TCP payload 重组出 `CIPH:<hex>`，用 `SHA256(keymat || BE32(counter))` 生成计数器流异或，命中 `ISCC{32hex}` 即为 flag。

## 原理

- **本地时间到 UTC 的多解性**：日志给的是本地时间，换算 UTC 需要时区偏移；跨国际日期变更线（IDL）后日期可能少一天，提示中的 `DATE_CORR=-1DAY` 与 `IDRULE:idx26_applied_to_idx>=27_only` 说明修正只对部分行生效，因此要按行枚举而不是全局套一个偏移。
- **KEYMAT 模板**：`AURORA-ER|flight=LX-517|syn=<EVT_A_UTC>|idl=<EVT_B_UTC>|a2=<EVT_C_UTC>` 把三个时间锚点拼成密钥材料；模板本身来自日志末尾的长 Base64，解码后还给出 `REASM:SEQ_ORDER|frag=3`（按序号重组 3 段）和 `UTC:local+date_corr-timezone`。
- **SHA256-CTR 流**：对每个 32 字节块计算 `SHA256(keymat + struct.pack(">I", i))`，拼成与密文等长的 keystream，再逐字节异或；这等价于以 SHA256 为 PRF 的 CTR 模式，计数器从 0 开始、大端 4 字节。
- **可验证性**：明文格式固定为 `ISCC{32hex}`，穷举候选后只需正则全匹配即可判定命中，不需要人工看结果。

## 触发条件

- 附件同时包含结构化日志与 pcap；日志有事件类型/经纬度/本地时间字段，末尾有长 Base64 提示。
- pcap 的 TCP payload 中出现 `CIPH:<hex>` 文本，且可能被分片成多段。
- 提示明确给出 KEYMAT 模板与算法参数。

## 利用步骤

1. 从日志中正则提取长度 ≥80 的 Base64 串，解码后确认包含 `KEYMAT:` 与 `ALGO:`。
2. 解析日志行（如 `idx,local_dt,lat,lon,...,event,detail`），筛出 `EVT_A`、`EVT_B`、`EVT_C`（`marker=A2` 或 `X9`）。
3. 对每条事件按经度估算时区（`round(lon/15)`，边界经度补 ±12/13/14 等），并枚举 `date_corr` 为 0 与 -1 天，得到 UTC epoch 候选集合。
4. 从 pcap 提取 TCP payload，按序号重组后正则 `CIPH:([0-9a-fA-F]+)`；若失败则直接在原始字节中搜索。
5. 对 `(syn, idl, a2)` 的笛卡尔积替换模板，生成 keymat；按块计算 SHA256 计数器流并异或密文。
6. 用 `re.fullmatch(rb"ISCC\{[0-9a-fA-F]{32}\}", plain)` 判定命中，输出 keymat 与 flag。

## PoC

```python
import hashlib, struct, re

def decrypt(ciphertext: bytes, keymat: str) -> bytes:
    blocks = (len(ciphertext) + 31) // 32
    keystream = b"".join(
        hashlib.sha256(keymat.encode() + struct.pack(">I", i)).digest()
        for i in range(blocks)
    )
    return bytes(c ^ k for c, k in zip(ciphertext, keystream))

# keymat = template.replace("<EVT_A_UTC>", str(syn))...
# 对候选 (syn, idl, a2) 逐一 decrypt，命中 ISCC{32hex} 即停止
```

## 变体与关联

- **时间变体**：时区可能是半小时/45 分钟偏移；日期修正可能是 +1 天；IDL 两侧的 `idx` 分界不同；事件可能用 UTC 而非本地时间。
- **算法变体**：计数器可能小端、从 1 开始、用 8 字节；PRF 可能是 HMAC-SHA256、SHA1 或 MD5；密文可能先 Base64/hex 编码。
- **重组变体**：pcap 可能是 pcapng、VLAN/QinQ、IP 分片或 TCP 乱序，需要按 TCP seq 排序；`CIPH:` 可能跨多个 segment。
- **关联卡片**：[[ctf-misc-png-trailing-data-lcg-xor-base62]]（LCG 流 XOR 解密密文）、[[ctf-forensics-tcp-urgent-pointer-covert-channel]]（TCP 字段隐写）。
- **边界**：若事件时间缺少经度/时区信息且提示未给规则，候选空间会爆炸；若密文长度不是 32 的倍数，最后一个块需截断。

## 检测与防御

- **CTF 验证**：先确认 Base64 提示能解出 KEYMAT/ALGO，再确认 pcap 能取到完整 CIPH，最后看命中候选的 keymat 是否由真实事件时间构成。
- **防御**：不要用“模板 + 可预测计数器”的裸 SHA256 流加密，改用 AEAD（AES-GCM/ChaCha20-Poly1305）并加入随机 nonce；日志中不要泄露密钥材料模板。
- **检测信号**：日志与流量中出现 `KEYMAT`、`CIPH:` 等自定义标记；大量短 TCP 段承载同一文本。
