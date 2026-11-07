---
id: ctf-reverse-apk-native-custom-rc4-sbox-rle-credential
title: APK native 自定义 RC4：S 盒初始化为 [1..255,0] + 6 字节 key，解出凭证后再反向 RLE 还原 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: apk-native-rotated-sbox-rc4-reverse-rle
aliases:
- ezapk
- 自定义 S 盒 RC4
- S = list(range(1,256)) + [0]
- 反向 RLE
- VEHICLE_ACCESS_GRANTED
tags:
- ctf
- reverse
- apk
- android
- native
- rc4
- sbox
- rle
- jni
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:38:58+08:00'
  notes: 已对照原文核对：native validateVehicleAccess、S=[1..255,0]、key=11 22 33 44 55 66、26 字节模板、反向 RLE 均与原文及 exp 截图一致；本机复跑 PoC，原文密文末字节 1D 解出末字符为 ~，按原文最终 flag 校正为 1E 后在卡中注明，脚本输出 flag{ccan_cccneeeede_careeee!?}。
---

## 一句话结论

APK 的 native 校验没有用标准 RC4：S 盒初始化是 `[1,2,...,255,0]`（把 0 移到末尾的旋转表），密钥固定为 6 字节 `11 22 33 44 55 66`，KSA/PRGA 其余部分与标准 RC4 相同；用同一套初始化生成密钥流解密 26 字节密文，得到一段带数字后缀的凭证，再做一次反向 RLE（`c2`→`cc`、`c3`→`ccc`、`e4`→`eeee`）即可还原 flag。

## 原理

- **native 校验入口**：Jadx 中 `MainActivity` 调用 native `validateVehicleAccess(input)`；返回值与 `"VEHICLE_ACCESS_GRANTED"` 比较，说明核心逻辑在 `libmyapplication.so`，Java 层只是桥接。
- **自定义 S 盒**：标准 RC4 初始化 `S[i]=i`（i=0..255）；本题把 0 移到末尾，`S = [1,2,...,255,0]`。KSA 仍按 `j=(j+S[i]+key[i%len])&0xFF` 交换，PRGA 仍按 `i=(i+1)&0xFF`、`j=(j+S[i])&0xFF` 交换并输出 `S[(S[i]+S[j])&0xFF]`。因此只需把初始化同步到解密脚本，其余逻辑可直接复用。
- **固定密钥与模板**：密钥为 6 字节 `11 22 33 44 55 66`；密文/模板是 `.rodata` 中的 26 字节常量。native 将输入经同一 RC4 处理后与模板逐字节比较，全部相等才返回 `VEHICLE_ACCESS_GRANTED`。
- **RC4 自逆**：PRGA 产生的密钥流与数据异或，加解密同一函数；用相同 S 盒、密钥和密文即可解出明文。
- **反向 RLE**：解出的明文不是最终 flag，而是带“字符+数字”压缩的凭证（如 `c2`、`c3`、`e4`）；`rle_decode` 按“字符后跟数字表示重复次数”展开，`c2`→`cc`、`c3`→`ccc`、`e4`→`eeee`，得到最终 flag。
- **为什么可逆**：RC4 的 KSA/PRGA 是确定性算法；S 盒、密钥、密文都能从 SO/流量中静态提取或动态 dump；RLE 是纯文本展开，逆变换唯一。
- **实现坑**：SO 中 S 盒可能以 256 字节数组/多个 `xmmword` 常量出现（本题 `xmmword_F1E0` 到 `F2D0`）；IDA 导出时注意前导零和字节序；Python 中 key 用 `bytes` 索引得到整数，S 盒用 `list` 复制，避免原地修改影响后续。

## 触发条件

- APK 校验在 native 层，Jadx 只看到 `native` 方法与 `System.loadLibrary`。
- SO 中存在 256 字节 S 盒常量、KSA/PRGA 两段 256 次循环、固定密钥；与标准 RC4 的差异仅在 S 盒初始化（或轮数/取模）。
- 能拿到密文/模板（从 `.rodata` 或 native 比较处 dump），且明文是 flag/凭证格式。
- 明文可能再做一层简单编码（RLE/hex/base64），需要按输出特征继续解码。

## 利用步骤

1. Jadx 打开 APK，定位 `MainActivity`/`validateVehicleAccess`，确认输入长度与 native 库名（`libmyapplication.so`）。
2. IDA/Ghidra 打开 SO，定位 JNI 导出函数 `Java_..._validateVehicleAccess`；找到 S 盒初始化、KSA、PRGA 与固定密钥。
3. 记录魔改：`S = list(range(1,256)) + [0]`、`key = 11 22 33 44 55 66`、密文/模板的 26 字节常量；确认 PRGA 输出下标与标准 RC4 一致。
4. 用 Python 实现同一套 `rc4_keystream`，对密文异或得到明文；若明文含 `c2`/`e4` 等“字符+数字”模式，说明还有 RLE。
5. 实现反向 RLE：逐字符读取，若后面跟数字则重复该字符该次数，否则重复 1 次。
6. 得到最终 flag/凭证；用正向 RC4 + RLE 编码回密文，验证脚本正确。
7. 如 S 盒/密钥在运行时才组装，可用 Frida hook JNI 函数打印入参/返回值，或 dump 初始化后的 S 盒。

## PoC

```python
def rc4_keystream(S, key, n):
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

def rle_decode(s):
    out, i = [], 0
    while i < len(s):
        ch = s[i]; i += 1
        num = ''
        while i < len(s) and s[i].isdigit():
            num += s[i]; i += 1
        out.append(ch * (int(num) if num else 1))
    return ''.join(out)

S = list(range(1, 256)) + [0]          # 非标准 S 盒：0 移到末尾
key = bytes([0x11,0x22,0x33,0x44,0x55,0x66])
cipher = bytes.fromhex("AF5068EC0A4F9F6FA7A4C42F4D48AD1379DFE44573FAEFA7F61E")  # 原文截图末字节为 1D，按最终 flag 的 `}` 校正为 1E

ks = rc4_keystream(S.copy(), key, len(cipher))
plain = bytes(c ^ k for c, k in zip(cipher, ks)).decode()
print(plain)              # flag{c2an_c3ne4de_care4!?} 形态
print(rle_decode(plain))  # flag{ccan_cccneeeede_careeee!?}
```

说明：密文/密钥来自文章样本，换题时需从目标 SO/流量重新提取；`plain` 的 `f1ag`/`flag` 以实际输出为准。原文截图的 26 字节密文末字节为 `1D`，按该 S 盒/密钥/密钥流解出末字符为 `~`；按原文给出的最终 flag `flag{ccan_cccneeeede_careeee!?}`，末字节应为 `1E`（其余 25 字节一致），上述 PoC 已按此校正。

## 变体与关联

- **S 盒变体**：`S[i]=i`、`S=[1..255,0]`、`S[i]=~i`、S 盒先做加法/异或再 KSA；只要把初始化同步到脚本即可，见 [[ctf-reverse-modified-rc4-rounds-sbox]]。
- **密钥变体**：固定 6 字节、从 Java 传入、从资源/签名派生；若密钥在运行时组装，用 Frida hook 或 dump 内存。
- **后处理变体**：RLE、hex、base64、反转、替换表；先看明文可打印性与模式（如 `c2`/`e4`），再决定下一步。
- 关联：[[ctf-reverse-rc4-inverted-sbox-add-xor-oracle-keystream]]（S[i]=~i 的 RC4 变种）、[[mobile-android-apk-ble-native-modified-rc4-vin]]（BLE VIN 场景的另一种变种 RC4）、[[ctf-reverse-modified-rc4-keytable-subtract-xor]]（密钥表与 PRGA 后处理魔改）。
- **边界**：若 S 盒/密钥由服务端动态下发、或 native 有反调试/加壳，静态还原成本上升；若明文不是 RLE 而是其他编码，按实际输出调整。

## 检测与防御

- **逆向侧**：看到 256 字节数组 + 两段 256 次循环 + 异或，先按 RC4 处理；重点比对 S 盒初始化、KSA 加法项、PRGA 输出下标与密钥。
- **防守侧**：客户端硬编码密钥/S 盒只能提高逆向成本，不能作为访问控制；服务端必须重新校验凭证，使用标准 AEAD 与设备证明。
- **检测思路**：APK/SO 中出现固定 256 字节 S 盒、`VEHICLE_ACCESS_GRANTED` 类明文字符串、`[1..255,0]` 旋转表、6 字节常量密钥；流量中出现固定长度十六进制凭证。
