---
id: crypto-hash-sha256-length-extension-append-field
title: SHA256 长度扩展：secret 前缀 MAC 追加字段并伪造摘要
type: scenario
domain: crypto
path: crypto/hash
technique: sha256-length-extension-secret-prefix-append
tags:
- sha256
- hash
- length-extension
- secret-prefix
- mac-forgery
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:48:19+08:00'
  notes: '已对照原文脚本与图58核对：secret 前缀 SHA256 长度扩展，Element: Lead 追加 ; Element: Gold，secret_len 10-60 枚举，base64(消息)|摘要 提交成功取得 flag；未复跑服务'
url: /docs/crypto/hash/crypto-hash-sha256-length-extension-append-field/
draft: false
kb_aliases:
- SHA256 长度扩展
- hash length extension
- secret-prefix MAC 伪造
- 追加 Element Gold
- hashpump
---

## 一句话结论

服务端用 `SHA256(secret || message)` 作为完整性校验，并把 `message` 与摘要一起交给客户端时，攻击者不需要知道 secret：以已知摘要为初始状态、按 `secret_len + len(message)` 构造 SHA256 padding，再压缩追加的 `; Element: Gold`，就能得到 `SHA256(secret || message || padding || extra)` 的合法摘要，让服务端接受被追加字段的伪造消息。

## 原理

- SHA256 是 Merkle-Damgård 结构：消息按 64 字节分组，每块用 256 位内部状态压缩；最终摘要就是处理完所有分组后的内部状态。
- 给定 `h = SHA256(secret || message)`，攻击者可以把 `h` 直接作为“处理完 `secret || message` 后”的初始状态，继续压缩新的分组；新分组是 `padding || extra`，其中 padding 按原消息长度 `L = secret_len + len(message)` 生成：
  - 先追加 `0x80`；
  - 再补 `0x00` 直到长度 ≡ 56 (mod 64)；
  - 最后 8 字节大端写入 `L * 8`（比特长度）。
- 压缩完 `extra`（以及 extra 自身的 padding）后得到的摘要，正好等于 `SHA256(secret || message || padding || extra)`。攻击者把 `message || padding || extra` 作为新消息、新摘要提交，服务端的 `SHA256(secret || 新消息)` 计算会命中。
- `secret_len` 未知时，在合理范围内（示例 10–60）逐个尝试；每个长度生成不同 padding 和摘要，直到服务端返回成功/flag。
- 为什么不能用 HMAC：HMAC 有内层/外层两次哈希和密钥派生，简单长度扩展无法直接构造；`secret || message` 这种自制 MAC 才是目标。
- 传输注意：padding 是二进制（含 `0x80`、`0x00`），若协议只接受文本，需要 base64/hex 编码整个伪造消息；示例用 `base64(message)|hash` 传输。

## 触发条件

- 服务端用 `SHA256(secret || user_message)` 计算摘要，并与用户提交的摘要比较；secret 是固定前缀且长度在可爆破范围。
- 攻击者能获得至少一组合法的 `(message, hash)`（例如登录/命令接口返回的 seal），并能提交任意 `message` 与 `hash`。
- 服务端在摘要校验后，按消息内容做权限/字段判断（如包含 `Element: Lead` 后要求/奖励 `Element: Gold`）。
- 消息可包含二进制 padding，或协议支持 base64/hex 编码；若服务端对消息做严格文本解析/规范化，padding 可能被拒绝。

## 利用步骤

1. 获取一组合法 `(message, hash)`；记录 message 的原始字节长度（不是 base64 长度）。
2. 选定追加内容 `extra`（示例 `; Element: Gold`）；在 10–60 范围内枚举 `secret_len`。
3. 对每个 `secret_len`：
   - `L = secret_len + len(message)`；
   - 生成 `glue = 0x80 + 0x00 * ((56 - (L+1) % 64) % 64) + struct.pack('>Q', L*8)`；
   - 用 `hash` 初始化 SHA256 状态，压缩 `extra + pad(L + len(glue) + len(extra))`；
   - 得到 `new_hash`；
   - 提交 `base64(message + glue + extra) + '|' + new_hash`。
4. 观察响应：若返回 flag/成功/角色变化，即命中；若报错/摘要不匹配，换下一个 `secret_len`。
5. 若服务端消息格式是 JSON/查询串，把 `extra` 设计成合法字段（如 `&role=admin`），并把 padding 放在字段值之后；必要时对 padding 做 URL 编码。
6. 成功后可继续追加更多字段，或利用提升后的权限读取 flag。

## PoC

```python
import struct, base64, hashlib

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

def ror(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def pad(length):
    p = b'\x80' + b'\x00' * ((56 - (length + 1) % 64) % 64)
    return p + struct.pack('>Q', length * 8)

def sha256_extend(state, data):
    h = [int(state[i:i+8], 16) for i in range(0, 64, 8)]
    for off in range(0, len(data), 64):
        w = [0] * 64
        chunk = data[off:off+64]
        for i in range(16):
            w[i] = struct.unpack('>I', chunk[i*4:i*4+4])[0]
        for i in range(16, 64):
            s0 = ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = ror(w[i-2], 17) ^ ror(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff
        a,b,c,d,e,f,g,hh = h
        for i in range(64):
            t1 = (hh + (ror(e,6)^ror(e,11)^ror(e,25)) + ((e&f)^(~e&g)) + K[i] + w[i]) & 0xffffffff
            t2 = ((ror(a,2)^ror(a,13)^ror(a,22)) + ((a&b)^(a&c)^(b&c))) & 0xffffffff
            a,b,c,d,e,f,g,hh = (t1+t2)&0xffffffff, a, b, c, (d+t1)&0xffffffff, e, f, g
        h = [(x+y)&0xffffffff for x,y in zip(h, [a,b,c,d,e,f,g,hh])]
    return ''.join(f'{x:08x}' for x in h)

def forge(hash_hex, known_msg: bytes, extra: bytes, secret_len: int):
    glue = pad(secret_len + len(known_msg))
    new_hash = sha256_extend(hash_hex, extra + pad(secret_len + len(known_msg) + len(glue) + len(extra)))
    return known_msg + glue + extra, new_hash

# 已知合法消息与摘要；secret_len 未知时在 10..60 枚举
known = b'Element: Lead'
seal = '<64 hex chars from server>'
payload, new_hash = forge(seal, known, b'; Element: Gold', secret_len=16)
print(base64.b64encode(payload).decode(), new_hash)
```

```bash
# 也可用 hashpump/hash_extender；确认其支持 sha256
hashpump -s <seal> -d 'Element: Lead' -a '; Element: Gold' -k 16 --algorithm sha256
```

## 变体与关联

- 变体：SHA1、MD5、SHA512 等 Merkle-Damgård 哈希同样适用，只需替换压缩函数/常量；SHA3 等海绵结构不适用。
- 变体：secret_len 未知时枚举 0–128；若服务端对长度有校验，结合报错/时间侧信道缩小范围。
- 变体：消息是 JSON 时，追加 `,"role":"admin"}` 等合法字段；padding 可能破坏 JSON，需把 padding 放在字符串值/注释中，或选择基于行的协议。
- 关联卡片：[[crypto-hash-md5-length-extension-password-forge-admin]]（MD5 长度扩展 + SQLi 链）、[[crypto-hash-md5-length-extension-password-forge-admin]] 中的 padding 构造可对照。
- 边界：HMAC、`SHA256(secret || message)` 但服务端使用恒定时间比较且拒绝二进制 padding、或对消息做规范化/签名前后重新序列化时，本手法可能失效；需要按实际协议调整。

## 检测与防御

- 检测：代码审计搜索 `sha256(secret + message)`、`hashlib.sha256(key + data)` 等 secret-prefix 构造；检查服务端是否把消息与摘要一起交给客户端。
- 修复：使用 HMAC-SHA256（`hmac.new(secret, message, sha256)`）或 AEAD；不要用 `secret || message` 作为 MAC。
- 加固：对消息做严格解析/规范化并在签名前完成；拒绝包含异常控制字符/超长 padding 的消息；使用恒定时间比较；密钥长度足够且定期轮换。
- 边界：长度扩展不恢复 secret，只伪造“secret 前缀 + 已知消息 + 追加数据”的摘要；如果业务只信任消息中靠前的字段，追加字段可能无效，需确认服务端解析顺序。
