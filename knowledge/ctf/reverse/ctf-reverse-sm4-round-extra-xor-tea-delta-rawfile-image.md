---
id: ctf-reverse-sm4-round-extra-xor-tea-delta-rawfile-image
title: 魔改 SM4 逆向：轮函数额外异或 TEA delta + 双层 Base64 还原 rawfile 加密图片
type: scenario
domain: ctf
path: ctf/reverse
technique: sm4-round-extra-xor-tea-delta-rawfile-image
aliases:
- SM4 每轮多异或 0x9E3779B9
- 标准表魔改 SM4
- rawfile enc 解密
- 双层 base64 图片还原
- ValidateCiphertext
tags:
- ctf
- reverse
- sm4
- modified-crypto
- base64
- harmonyos
- native
- rawfile
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-19
  verified_at: '2026-11-08T12:12:39+08:00'
  notes: 已对照原文核对：img44/45 确认 getRK 与 iterate32 调用，img46 确认魔改点为轮函数结果额外异或 0x9E3779B9（S-box/FK/CK 全标准表），img47 CyberChef From Base64+To Hex 得密文 hex，img48 为转换后 11316 个 u32，img49 确认 MK={0xE52BCC34,0x1F1B5B18,0x5F1ED75A,0xF108FE7F} 填入解密程序，img50/51 解密输出再解一层 Base64，img52 得 PNG 图片，img53 上传后提示 flag=md5(锁密码+Harmony5337)。注：解密脚本中密文为手动填入（原文自述未写文件 IO），但密文来自题目 enc 资源文件且转换步骤完整，PoC 可复现。未验证点：脚本未在本机执行。
---

## 一句话结论

HarmonyOS 题把「正确图片」加密后放进 `resources/rawfile/enc`：外层是 Base64 文本，解码后是 2829 个 16 字节分组，用标准 S-box/FK/CK 的 32 轮 SM4 解密，但轮函数在写回新字时额外异或了 TEA 的 delta 常量 `0x9E3779B9`；按同一改动实现解密，再把结果做一次 Base64 解码即得到 PNG，把它上传即可通过 native 侧 `ValidateCiphertext` 的比对。

## 原理

- **为什么要找「期望值」**：`pages/index` 的按钮流程是：用户选图 → `onDataPrepared` 把图片字节 Base64 后写入 `bb.txt` → `secret_.ValidateCiphertext(readStringFromFile('bb.txt'), enc)` 比对。比对成功才跳 `pages/final`。因此攻击面不在「猜图片」，而在 native 侧的比较材料 `enc`——它随包分发。
- **确认算法家族**：native 函数调用 `getRK(MK,K,RK)` 生成轮密钥，随后 `iterate32(&block, RK)` 做 32 轮，最后 4 个字反序输出，并且 `functionB` 是 256 字节 S-box 查表、`functionL1` 是 `x ^ rol2 ^ rol10 ^ rol18 ^ rol24`、`functionL2` 是 `x ^ rol13 ^ rol23`——这四个 rotate 常量与 4 字状态是 SM4 的强指纹，即使被改过也能按 SM4 骨架还原。
- **唯一改动点**：`iterate32` 里写回的是
  `X[(i+4)%4] = X[i%4] ^ T(X[(i+1)%4] ^ X[(i+2)%4] ^ X[(i+3)%4] ^ RK[i]) ^ 0x9E3779B9`。
  标准 SM4 没有最后的 `^ 0x9E3779B9`。这个常量是 TEA/XXTEA 的 delta，属于常见的「混入另一种算法常量」混淆手法；它只影响每轮的中间值，不改变可逆性——只要解密时同样加上这一项、并把轮密钥逆序，就能逐步还原。
- **密钥**：`MK = {0xE52BCC34, 0x1F1B5B18, 0x5F1ED75A, 0xF108FE7F}`，S-box/FK/CK 均为标准 SM4 常量，无需替换表。
- **双层编码**：`enc` 文件本身是 Base64 文本（解码后是 45264 字节密文）；SM4 解出的明文仍是一段 Base64 文本，再解码才得到 `\x89PNG` 开头的图片。少解一层会看到大段可打印字符，是判断「还有一层编码」的直接线索。
- **字节序陷阱**：从十六进制文本还原 DWORD 时按小端装配（等价于 IDA `get_wide_dword`），输出时按大端逐字节写出（`p[3]..p[0]`）。这两处方向不一致，若明文乱码应优先检查这里，而不是怀疑密钥或轮数。

## 触发条件

- 目标是 HarmonyOS HAP，`resources/rawfile/` 下有可疑的二进制/文本资源（如 `enc`），native 库导出比对函数。
- 加密为对称分组算法且密钥/表全在包内。
- 校验逻辑是「上传内容 == 解密后的内置资源」，即期望值可由密文反推。

## 利用步骤

1. 解包 HAP，反编译 `modules.abc`，定位 `ValidateCiphertext(readStringFromFile('bb.txt'), enc)` 与 `transferResourceMgr(resMgr,'enc')`，确认 `enc` 来自 rawfile。
2. 提取 `libs/arm64-v8a/libsecret.so`，在 `.rodata` 找 `ValidateCiphertext`，跟随 `data.rel.ro` 的 `dq offset` 到实现函数（本题 `sub_8560`）。
3. 读实现：确认 `getRK`/`iterate32`/4 字反序，记录 `MK`、S-box/FK/CK 是否标准；逐行对比标准 SM4，标出轮函数末尾多出的 `^ 0x9E3779B9`。
4. 取出 `resources/rawfile/enc`，先 Base64 解码得到密文；按 16 字节分组，组内 4 个 DWORD 小端装配。
5. 用标准密钥扩展生成 32 个轮密钥，解密时逆序使用，轮函数保留额外的 delta 异或；每组解密后按大端写回字节、再反转 4 字顺序。
6. 把解密结果再做一次 Base64 解码，检查文件头是否为 `89 50 4E 47`；保存为 PNG。
7. 把该图片作为「正确图片」走正常上传流程，或直接把 `bb.txt` 内容替换为其 Base64 以通过比对。

## PoC

```python
import base64, struct

SBOX = [...]  # 标准 SM4 S-box，从 .rodata 或公开实现取
FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
CK = [...]    # 标准 32 项 CK

MK = [0xE52BCC34, 0x1F1B5B18, 0x5F1ED75A, 0xF108FE7F]
DELTA = 0x9E3779B9   # 本题在每轮写回时额外异或的 TEA 常量

def rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def tau(x):
    return (SBOX[(x >> 24) & 0xFF] << 24) | (SBOX[(x >> 16) & 0xFF] << 16) | \
           (SBOX[(x >> 8) & 0xFF] << 8) | SBOX[x & 0xFF]

def L1(x): return x ^ rol(x, 2) ^ rol(x, 10) ^ rol(x, 18) ^ rol(x, 24)
def L2(x): return x ^ rol(x, 13) ^ rol(x, 23)

def key_schedule(mk):
    K = [mk[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        K.append(K[i] ^ L2(tau(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i])))
        rk.append(K[i+4])
    return rk

def iterate32(X, rk):
    for i in range(32):
        t = L1(tau(X[(i+1) % 4] ^ X[(i+2) % 4] ^ X[(i+3) % 4] ^ rk[i]))
        X[(i+4) % 4] = (X[i % 4] ^ t ^ DELTA) & 0xFFFFFFFF

def decrypt_block(block, rk):
    X = list(struct.unpack('<4I', block))     # 小端装字
    iterate32(X, rk[::-1])                    # 轮密钥逆序
    return struct.pack('>4I', *X[::-1])       # 大端写出 + 4 字反序

def main(raw: bytes):
    rk = key_schedule(MK)
    ct = base64.b64decode(raw)
    pt = b''.join(decrypt_block(ct[i:i+16], rk) for i in range(0, len(ct), 16))
    img = base64.b64decode(pt)                # 第二层 Base64
    assert img[:4] == b'\x89PNG'
    open('recovered.png', 'wb').write(img)
```

## 变体与关联

- 变体：额外异或的常量可换成其他魔数（如 IP 校验和、时间戳），也可是「每轮异或轮号」；识别方法是把实现的轮函数与标准 SM4 逐项对齐，只保留差异项。
- 变体：分组加密外层可再套 RC4/XTEA 或多层 Base64；看到明文大段可打印且带 `=` 填充，说明还有编码层。
- 关联：[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（标准 SM4 + 小端装字）、[[ctf-reverse-custom-sm4-24round-native-so-decrypt]]（改轮数/表的变体）、[[ctf-reverse-multistage-pe-vm-modified-sm4]]（VM 中的魔改 SM4）、[[ctf-reverse-harmonyos-pattern-lock-napi-xxtea-recover]]（同一题的手势锁环节）。

## 检测与防御

- 本题无服务端攻击面；对产品而言，「内置密文 + 客户端比对」不能作为授权依据。
- 检测：HAP 的 `rawfile` 出现高熵或 Base64 大文本；native 中存在 256 字节 S-box 与 32 个 CK 常量、`rol2/10/18/24`；轮函数出现与 TEA delta 相同的常量。
- 防御：期望值应由服务端比对，客户端只提交凭据；敏感资源不要随包分发；如必须加密，使用标准算法 + 服务端密钥，并避免把「判定材料」和「判定逻辑」放在同一信任域。
