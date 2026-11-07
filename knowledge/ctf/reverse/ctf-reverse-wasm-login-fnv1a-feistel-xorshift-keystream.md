---
id: ctf-reverse-wasm-login-fnv1a-feistel-xorshift-keystream
title: WASM 前端登录校验逆向：FNV-1a 用户名 + 8 轮 Feistel 逆解密码 + xorshift64* 密钥流解密
type: scenario
domain: ctf
path: ctf/reverse
technique: wasm-login-fnv1a-feistel-xorshift-keystream
aliases:
- WebAssembly 逆向
- release.wasm
- authenticate
- FNV-1a 32
- Feistel16
- xorshift64*
- 密钥流解密
tags:
- ctf
- reverse
- wasm
- feistel
- fnv1a
- xorshift
- keystream
- crypto
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:53:47+08:00'
  notes: 已对照原文WebAssembly题核对：FNV-1a 0x477DDD25/Et11an、derive_keys常量、8轮Feistel及逆解、TARGET与39字节密文、seed=LE64(TARGET)^keys[0]^A5A5、xorshift64*密钥流一致；未验证点：PoC未本机执行。
---

## 一句话结论

前端 WASM 导出的 `authenticate` 先用 FNV-1a 32 校验用户名（固定 `0x477DDD25`），再用用户名派生 8 个 64 位轮密钥，对 16 字节密码做 8 轮自制 Feistel 并要求结果等于固定 `TARGET`；由于 Feistel 每轮可逆，可从 `TARGET` 反推出密码；同时 `TARGET` 前 8 字节与 `keys[0]` 异或得到 seed，xorshift64* 生成密钥流异或固定密文即得 flag，因此不输入正确密码也能直接还原 flag。

## 原理

- **加载结构**：`index.html` 引入 `crypto-js.js`（只用于计算并显示 SHA1 ticket，与校验无关）、`release.js`（`fetch` + `WebAssembly.instantiate`，导出 `malloc/free/memory/authenticate`，并用 `cwrap` 做 JS string 到 WASM 线性内存的分配/拷贝/释放）。核心逻辑全部在 `release.wasm` 的 `authenticate(user, pass, out_ptr, out_len)` 中；逆向时应忽略 ticket，直接从 `authenticate` 入手。
- **用户名校验（FNV-1a 32）**：
  - `h = 0x811C9DC5`；
  - 对每个字节：`h ^= byte; h = (h * 0x01000193) mod 2^32`；
  - 要求 `h == 0x477DDD25`。可以用字典/用户名枚举找到满足的字符串（题目中为 `Et11an`），或直接绕过该检查。
- **用户名派生轮密钥**：
  - 初始状态 `s = 0xC3A5C85C97CB3127`；
  - 对用户名每个字节 `c`：`s ^= (c + 0x9E3779B97F4A7C15 + (s << 6) + (s >> 2)) mod 2^64`，再 `s = rotl64(s, 9) ^ (s >> 3)`；
  - 再做 8 轮 xorshift 混合，每轮生成一个轮密钥：
    `s ^= s >> 12; s ^= s << 25; s ^= s >> 27; keys[r] = (s * 2685821657736338717) mod 2^64`。
- **密码校验（自制 Feistel，8 轮）**：
  - 要求密码恰好 16 字节；`L = LE64(pass[0:8])`，`R = LE64(pass[8:16])`；
  - 每轮：`f = round_f(R, keys[r])`，`(L, R) = (R, L ^ f)`；
  - `round_f`：`x += k; x ^= rotl64(x,17); x += rotl64(x,41); x ^= x >> 23; x *= 0x9E3779B97F4A7C15; x ^= x >> 27`（全部 mod 2^64）；
  - 要求输出 `(L, R)` 等于固定 `TARGET`（16 字节）。
  - **求逆**：已知 `newL = R`、`newR = L ^ f(R, k)`，则逆推为 `R = newL`、`L = newR ^ f(newL, k)`；从 `r=7` 倒序执行 8 次即可从 `TARGET` 恢复 16 字节密码。
- **flag 解密（xorshift64* 密钥流）**：
  - `seed = LE64(TARGET[0:8]) ^ keys[0] ^ 0xA5A5A5A5A5A5A5A5`；
  - 每 8 字节迭代：`x ^= x >> 12; x ^= x << 25; x ^= x >> 27; x *= 2685821657736338717`，按小端输出 8 字节；
  - `flag = FLAG_CIPHERTEXT XOR keystream`（密文 39 字节）。
- **为什么可以绕过登录**：用户名只影响 `keys`，密码只用于和 `TARGET` 比较，而 flag 的 seed 直接由 `TARGET` 与 `keys[0]` 计算；只要知道用户名（或恢复 `keys`），就能跳过密码校验直接解密 flag。反过来，若想通过登录，只需用 Feistel 逆推得到密码。
- 注意区分「轮密钥」与「密钥流」：轮密钥由用户名派生并在 Feistel 每轮使用；密钥流由 seed 经 xorshift64* 生成，直接与密文异或，二者来源和用途不同。

## 触发条件

- 目标是前端 WASM 登录/许可校验，HTML 通过 `WebAssembly.instantiate` 加载 `.wasm`，导出 `authenticate`/`verify` 等函数。
- 用户名/账号先用短哈希（FNV-1a 32、CRC32 等）校验，哈希常量在 WASM 中可见。
- 密码经过分组变换（Feistel/ARX/自定义轮函数），轮密钥由用户名或固定常量派生。
- 校验通过后由 WASM 写出 flag/令牌，且输出由可复现的 PRNG 密钥流或固定密文决定。

## 利用步骤

1. 解包前端资源，阅读 HTML/JS：确认 `release.js` 的加载流程、`cwrap` 参数类型、`authenticate` 的签名与输出缓冲区；把 SHA1 ticket 等展示逻辑排除。
2. 用 `wasm2wat`、Ghidra/WASM 插件或 `wasm-decompile` 反编译 `release.wasm`，定位 `authenticate` 及导出的 `malloc/free/memory`。
3. 恢复用户名校验：识别 FNV-1a 常量 `0x811C9DC5`/`0x01000193` 与目标 `0x477DDD25`；用字典或枚举找到用户名（或 patch 掉检查）。
4. 恢复 `derive_keys_from_user`：确认初始常量、逐字节混合公式、8 轮 xorshift 混合与乘数 `2685821657736338717`。
5. 恢复 Feistel：确认轮函数各步、轮数、轮密钥顺序、输入/输出字节序（小端）与 `TARGET` 常量。
6. 从 `TARGET` 倒序执行 Feistel 逆变换得到 16 字节密码；用 `user + password` 调用 `authenticate` 验证登录成功并取得 flag（路线 A）。
7. 或跳过密码：直接 `seed = LE64(TARGET[0:8]) ^ keys[0] ^ 0xA5A5A5A5A5A5A5A5`，用 xorshift64* 生成 39 字节密钥流，与 `FLAG_CIPHERTEXT` 异或得到 flag（路线 B）。
8. 用 flag 格式（前缀、可打印字符、长度）校验结果；必要时把恢复的 flag 与 WASM 实际输出交叉比对。

## PoC

```python
MASK64 = 0xFFFFFFFFFFFFFFFF

def rotl64(x, r):
    return ((x << r) & MASK64) | (x >> (64 - r))

def fnv1a32(s: str) -> int:
    h = 2166136261
    for b in s.encode():
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h

def round_f(x, k):
    x = (x + k) & MASK64
    x ^= rotl64(x, 17)
    x = (x + rotl64(x, 41)) & MASK64
    x ^= (x >> 23)
    x = (x * 0x9E3779B97F4A7C15) & MASK64
    x ^= (x >> 27)
    return x & MASK64

def derive_keys_from_user(user: str):
    s = 0xC3A5C85C97CB3127
    for c in user.encode():
        s ^= (c + 0x9E3779B97F4A7C15 + ((s << 6) & MASK64) + (s >> 2)) & MASK64
        s = (rotl64(s, 9) ^ (s >> 3)) & MASK64
    keys = []
    for _ in range(8):
        s ^= (s >> 12)
        s ^= ((s << 25) & MASK64)
        s ^= (s >> 27)
        keys.append((s * 2685821657736338717) & MASK64)
    return keys

def feistel_inv_from_target(mixed16: bytes, keys):
    L = int.from_bytes(mixed16[:8], "little")
    R = int.from_bytes(mixed16[8:], "little")
    for r in reversed(range(8)):
        oldR = L
        f = round_f(L, keys[r])
        oldL = (R ^ f) & MASK64
        L, R = oldL, oldR
    return L.to_bytes(8, "little") + R.to_bytes(8, "little")

def xorshift_stream(seed: int, n: int) -> bytes:
    out = bytearray()
    x = seed & MASK64
    while len(out) < n:
        x ^= (x >> 12)
        x ^= ((x << 25) & MASK64)
        x ^= (x >> 27)
        x = (x * 2685821657736338717) & MASK64
        out.extend(x.to_bytes(8, "little"))
    return bytes(out[:n])

USER_HASH = 0x477DDD25
target = bytes.fromhex("9f3cc3766f84cbae51993fbf15634b66")
cipher = bytes.fromhex(
    "90cf444a5da45f8c87d542012ebcbf5a"
    "54546b92cc67ac56bc06a67c16ee0de6"
    "611cfbc6395584"
)

user = "Et11an"                     # 满足 fnv1a32(user) == USER_HASH
assert fnv1a32(user) == USER_HASH

keys = derive_keys_from_user(user)
password = feistel_inv_from_target(target, keys)
print("password:", password.decode())

seed = int.from_bytes(target[:8], "little") ^ keys[0] ^ 0xA5A5A5A5A5A5A5A5
ks = xorshift_stream(seed, len(cipher))
flag = bytes(a ^ b for a, b in zip(cipher, ks))
print("flag:", flag.decode())
```

说明：以上为按反编译语义重写的结构化 PoC，未在本机执行；`TARGET`、密文与用户名为题目常量，实际目标需从 WASM 数据段重新提取。

## 变体与关联

- **哈希变体**：FNV-1a 32/64、CRC32、自定义滚动哈希；短哈希通常可碰撞，但若要拿到 flag，仍需走派生链或输出约束。
- **分组变换变体**：Feistel 轮数/轮函数不同、XTEA/TEA、ARX 置换；求逆时按“最后一轮先逆”的顺序，注意小端装载与 64 位掩码。
- **密钥流派生变体**：xorshift64*、MT19937、LCG、ChaCha20；关键是恢复 seed 公式与输出字节序。
- **绕过路线变体**：路线 A 输入正确账号密码让程序自行输出；路线 B 直接复现 flag 解密链；也可 patch WASM 中的比较分支，或 hook `authenticate` 返回值。
- **关联卡片**：[[ctf-reverse-electron-asar-wasm-license-hash-collision-z3]]（Electron + WASM 许可证哈希碰撞）、[[ctf-reverse-ransomware-xor-crc32-mt19937-keystream]]（seed 派生密钥流解密）、[[ctf-reverse-cpp-vtable-modified-tea-mask-xor]]（C++ 魔改分组算法逆向）、[[ctf-reverse-android-ue-pak-encrypted-wasm-native-vm-co-simulation]]（WASM 与原生 VM 协同逆向）。
- **边界**：若 flag 由服务端下发、seed 含服务端随机数，或 WASM 使用不可逆签名校验，则纯客户端复现不成立；若 WASM 被混淆/字节码加密，需要先解包或动态 dump 内存。

## 检测与防御

- **CTF/验证**：恢复的 flag 应有明确格式且可打印；路线 A 调用 `authenticate` 应返回 1 并输出同一 flag；路线 B 的解密结果应与路线 A 一致。
- **检测信号**：前端 WASM 中出现 `authenticate`/`verify` 导出、FNV-1a 常量 `0x811C9DC5`/`0x01000193`、Feistel 轮函数常量 `0x9E3779B97F4A7C15`、xorshift 乘数 `2685821657736338717`、固定 `TARGET` 与密文数组。
- **防御视角**：前端校验不能作为安全边界。许可证/登录应由服务端验证，flag/密钥由服务端按会话下发；不要把完整解密链和固定密文放在客户端 WASM 中。
- **加固边界**：WASM 混淆、字符串加密、控制流平坦化只提高逆向成本；只要客户端能离线判定并输出结果，攻击者就能复现同一计算。
