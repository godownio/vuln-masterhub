---
id: ctf-reverse-pyarmor-pyinstaller-custom-xtea-carlotta
title: PyInstaller + pyarmor 1shot 还原源码：逆自定义 XTEA 与 Carlotta 变换解密
type: scenario
domain: ctf
path: ctf/reverse
technique: pyarmor-pyinstaller-custom-xtea-carlotta
tags:
- ctf
- reverse
- pyinstaller
- pyarmor
- xtea
- carlotta
- rc4
- deobfuscation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:21+08:00'
  notes: 已对照原文与全部 89 张图片核对；拆分为 PLUS 与 ez_py 两道独立题并纠正混合链；未在本机复现
url: /docs/ctf/reverse/ctf-reverse-pyarmor-pyinstaller-custom-xtea-carlotta/
draft: false
kb_aliases:
- pyarmor 1shot 反混淆
- PyInstaller pyc 提取
- 自定义 XTEA 变种
- Carlotta 变换求逆
- RC4-like 解密
---

## 一句话结论

这篇 wp 包含两个独立的 Python 逆向题：案例一从 PyInstaller exe 提取 `key.pyc`，用 PyLingual 恢复源码后逆 9 个 32 位块的自定义 XTEA（`delta=0x87456123`，`key=2025` 派生 4 个字）与 Carlotta 16 位混合变换，先逆 XTEA 再对 Carlotta 做 65536 次前像搜索恢复 9 个 key；案例二用 pyarmor-1shot 还原 pyarmor 混淆源码，再用 RC4-like 密钥流解密。两题共享“还原 Python 源码 + 逆自定义密码”的思路，但不是同一条链。

## 原理

- **PyInstaller/PyLingual（案例一）**：exe 内是 CArchive/PYZ，`pyinstxtractor` 可提取 `key.pyc`；PyInstaller 的 pyc 头部可能被剥离，需要按 Python 版本补 magic/时间戳，再用 PyLingual 等反编译。案例一的 `key.pyc` 由此得到。
- **pyarmor（案例二）**：pyarmor 对 code object 做加密与运行时解密；`pyarmor-1shot` 等工具可在静态/动态条件下还原出较完整的 Python 源码。案例二用该工具还原后得到 RC4-like 解密逻辑与密文。
- **自定义 XTEA（案例一）**：`encrypt(v0,v1,key=2025)` 使用 `delta=0x87456123`、32 轮，key0..key3 由 2025 与 `0x12345678/0x87654321/0xABCDEF00` 派生；解密按相反顺序减去轮函数并递减 sum。
- **Carlotta 变换（案例一）**：把 32 位块拆成两个 16 位，用 `E=i+2025`、`F=i*i` 与常量 `0x12345678` 做两轮混合；逆变换没有解析解，但状态空间只有 2^16，可枚举 D 求前像 (C,D)。
- **案例一整体流程**：9 个 key 先经 Carlotta 变换，再相邻两两做 XTEA 加密（8 次），输出 9 个 32 位值；逆向即反向解密 XTEA、再逐块求 Carlotta 逆，得到 9 个 key；最终 flag 由恢复出的 key 经字符表映射/生成器得到。
- **RC4-like（案例二）**：案例二把 39 个密文字符与 `key=[1234,5678,9123,4567,8912,3456,7891,2345,6789]` 做 RC4-like S 盒/keystream 生成，按 `cipher[i] ^ (keystream[i] + modifier)` 解密，modifier 在偶数位取 key、奇数位取 `key*2 % 0xFFF`。

## 触发条件

- 案例一：目标是 PyInstaller 打包的 Python exe，能提取 `key.pyc` 并用 PyLingual/反编译器还原；案例二：目标是 pyarmor 混淆的 Python 程序，可用 pyarmor-1shot 或运行时 dump 还原。
- 加密逻辑带自定义分组密码/变换，密钥或常量可从还原后的源码获得。
- 有足够已知明文/目标输出（`target_output`、`cipher`）用于验证解密结果。

## 利用步骤

1. 案例一：`pyinstxtractor` 解包 exe，提取 `key.pyc`；按 Python 版本补 pyc 头后用 PyLingual 反编译（原文在线反编译不完整时，再按字节码补逻辑）。
2. 案例一：从源码提取 `target_output`、XTEA 参数（`delta=0x87456123`、`key=2025`）与 Carlotta 常量。
3. 案例一：逆 XTEA：从最后一组开始，`decrypt(v0,v1)` 得到相邻块的中间值。
4. 案例一：对每个中间值拆高/低 16 位，调用 `carlotta_inverse_transform(P,Q,E,F)` 枚举 D（0..65535）恢复 (C,D)，合并为 32 位 key；再用字符表/生成器验证得到 flag。
5. 案例二：用 pyarmor-1shot 还原源码，提取 `cipher` 与 RC4-like 密钥。
6. 案例二：用密钥初始化 S 盒与 keystream，按 `cipher[i] ^ (keystream[i] + modifier)` 解密得到 flag。

## PoC

关键逆函数（节选）：

```python
def decrypt(v0, v1, key=2025):
    delta = 0x87456123
    key0 = key & 0xFFFFFFFF
    key1 = ((key >> 8) ^ 0x12345678) & 0xFFFFFFFF
    key2 = ((key << 4) ^ 0x87654321) & 0xFFFFFFFF
    key3 = ((key >> 12) ^ 0xABCDEF00) & 0xFFFFFFFF
    s = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + key2) ^ (v0 + s) ^ ((v0 >> 4) + key3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + key0) ^ (v1 + s) ^ ((v1 >> 4) + key1))) & 0xFFFFFFFF
        s = (s - delta) & 0xFFFFFFFF
    return v0, v1

def carlotta_inverse(P, Q, E, F):
    H = 0x12345678
    I, J = E & 0xFFFF, (E >> 16) & 0xFFFF
    K, L = (E ^ F) & 0xFFFF, ((E >> 8) ^ F) & 0xFFFF
    M = (H * (F + 1)) & 0xFFFFFFFF
    for D in range(1 << 16):
        N1 = ((D << 5) + I) ^ (D + M) ^ ((D >> 5) + J)
        C = (P - N1) & 0xFFFF
        N2 = ((P << 5) + K) ^ (P + M) ^ ((P >> 5) + L)
        if ((D + N2) & 0xFFFF) == Q:
            return C, D
```

案例一完整流程见题目脚本：逆 XTEA → 逐块 Carlotta 逆 → 字符表映射；案例二完整流程见还原后的源码：RC4-like KSA/PRGA → 逐字节 XOR。

案例二关键参数（节选，完整密文见原文）：

```python
cipher = [1473, 3419, 9156, 1267, 9185, 2823, 7945, 618, 7036, 2479, 5791, 1945,
          4639, 1548, 3634, 3502, 2433, 1407, 1263, 3354, 9274, 1085, 8851, 3022,
          8031, 734, 6869, 2644, 5798, 1862, 4745, 1554, 3523, 3631, 2512, 1499,
          1221, 3226, 9237]
key = [1234, 5678, 9123, 4567, 8912, 3456, 7891, 2345, 6789]
# init/make 生成 256 字节 keystream；偶数位 modifier=key[i%9]，
# 奇数位 modifier=(key[i%9]*2) % 0xFFF
```

## 变体与关联

- 自定义分组密码可换成 XXTEA、TEA 变种、SM4 变体；关键是识别 delta、轮数、key 派生。
- pyarmor 版本不同，1shot/动态 dump 的适配不同；也可在运行时 hook 解密函数导出 code object。
- 案例一/案例二来自同一 wp 的两道独立题：前者是“PyInstaller + 自定义分组密码”，后者是“pyarmor + RC4-like 流密码”；可分别套用，不要混为一条链。
- 关联：PyInstaller marshal + XXTEA 解密、pyarmor 混淆还原、自定义变换求逆。

## 检测与防御

- 恶意样本分析：识别 PyInstaller/Pyarmor 特征，优先动态 dump 解密后的 code object。
- 对自定义密码实现，先找常量（delta、S 盒、固定表）再逆轮函数；空间小的变换可暴力前像。
- 防御方避免仅依赖混淆/自定义密码保护敏感逻辑，使用标准密码库与密钥管理。
