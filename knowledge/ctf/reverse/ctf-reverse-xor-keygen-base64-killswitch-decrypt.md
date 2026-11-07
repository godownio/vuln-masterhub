---
id: ctf-reverse-xor-keygen-base64-killswitch-decrypt
title: 恶意样本 killswitch 域名解密：复现 7*n+66 密钥生成循环 + Base64 + 循环 XOR
type: scenario
domain: ctf
path: ctf/reverse
technique: keygen-loop-xor-base64-config-decrypt
aliases:
- killswitch 域名解密
- XOR 密钥生成循环
- 7*n+66 密钥
- base64 循环 XOR
- 恶意样本配置还原
- The Payload killswitch
tags:
- reverse
- malware
- xor
- base64
- keygen
- killswitch
- ctf
- ida
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:33:24+08:00'
  notes: 已对照原文 The Payload 题5/10与图18-24核对：IDA 中密钥循环 target[n]=7*n+66 (n<0x20)，Base64 KXgmYHMADxsV8uHiuPPB3w== 经循环 XOR 解出 k1v7-echosim.net，flag HTB{Eternal_Companions_Reunited_Again}；按 (7n+66)%256 复算密钥与明文均一致。未验证点：未运行样本，仅静态复算。
---

## 一句话结论

当恶意样本用一段确定性的密钥生成循环（本例 `key[n] = 7*n + 66`，n=0..31）生成 32 字节 XOR 密钥，再对 Base64 编码的内置配置做循环异或时，只要在 IDA 中还原该循环并用 Python 复现密钥、Base64 解码后逐字节 XOR，就能静态解出 killswitch 域名（本例 `k1v7-echosim.net`），无需运行样本。

## 原理

- 逆向代码中的密钥生成分支：`target._Mypair._Myval2._Bx._Buf[n0x20] = 7 * n0x20 + 66; ++n0x20; while (n0x20 < 0x20);`，即生成 32 字节密钥，第 n 字节为 `7n + 66`。C++ 中该值写入 char 会按字节回绕，Python 复现时对 256 取模即可。
- 加密/解密是对称的：配置先 Base64 编码，再用该 32 字节密钥循环异或（密钥按位置 `i % 32` 重复）。样本中的 Base64 串 `KXgmYHMADxsV8uHiuPPB3w==` 解码后为 16 字节密文，与密钥前 16 字节异或即得到可打印域名。
- 该方法成立的前提是密钥生成算法在二进制中是固定常量/确定性循环，且解密逻辑使用同一密钥；若样本使用机器相关种子或非对称加密，则不能直接复现。
- 文章还展示了另一种调用路径：`ScanAndSpread` 中通过 `call qword ptr [rax+60h]` 等间接调用执行解密后的 payload；本题只需静态解出域名并在 Docker 中屏蔽该 killswitch 域名即可取 flag（HTB{Eternal_Companions_Reunited_Again}）。
- 关键点：识别“密钥生成循环”比盯着 Base64 串更有效；先恢复密钥，再尝试对样本中所有 Base64/高熵字符串做解密验证。

## 触发条件

- 拿到恶意样本二进制，具备静态反汇编/反编译环境（IDA/Ghidra）。
- 样本把配置或 C2/killswitch 域名以“Base64 + XOR”形式内嵌，密钥由可识别的循环生成。
- 密钥生成不依赖运行时环境（否则需动态提取）。

## 利用步骤

1. 在 IDA 中定位解密函数/配置读取路径，查找对内置字符串的引用与 Base64 解码调用。
2. 找到密钥生成循环（本例 `7 * n + 66`，n < 0x20），记录常量与迭代次数。
3. 用 Python 按字节回绕复现密钥：`key[n] = (7*n + 66) % 256`。
4. 取样本中的 Base64 密文，Base64 解码后用密钥循环异或；过滤不可打印字符得到域名/URL。
5. 用明文验证结果（域名格式、字符串引用），并在隔离环境用 hosts/Docker 屏蔽该域名观察样本行为。

## PoC

```python
import base64

def gen_key(n=32):
    return bytes((7 * i + 66) % 256 for i in range(n))

def decrypt(b64, key):
    data = base64.b64decode(b64)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

key = gen_key()
print(key.hex())  # 424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b
print(decrypt("KXgmYHMADxsV8uHiuPPB3w==", key).decode(errors="ignore"))
# 输出：k1v7-echosim.net
```

```text
# 文章实测：密钥前 9 字节为 ASCII "BIPW^elsz"，其余为非打印字节
# Base64 解码密文：2978266073000f1b15f2e1e2b8f3c1df
# 解密结果：k1v7-echosim.net（killswitch 域名）
```

## 变体与关联

- 变体：编译器可能生成 AVX 向量化分支（样本中另有 `_mm_load_si128` 路径），但密钥序列相同；需按相同常量复现。
- 变体：密钥长度可能不是 32、常量可能是乘加组合；先确定循环边界与写入宽度（byte/word）。
- 关联：[[tools-ida-xor-string-call-arg-backtrack-decrypt]]（IDAPython 批量回溯 XOR 字符串解密调用点）；[[ctf-forensics-phishing-email-xor-docx-base64-key]]（从正文 Base64 取密钥解 DOCX 的同类组合）。
- 边界：本卡针对确定性密钥循环；若密钥来自随机数、注册表或远程下发，需动态调试/内存取证提取。

## 检测与防御

- 检测/分析：YARA 可匹配“乘加循环生成字节数组 + Base64 解码 + 异或”的样本特征；沙箱中阻断可疑 killswitch 域名并观察样本是否自毁/退出。
- 防御：在网关/DNS 层屏蔽恶意域名；对样本做静态解密而不是直接执行；把解出的 IOC 加入检测规则。
- 响应：若样本已在环境中执行，检查其是否因 killswitch 域名可达而删除/潜伏，按解出的域名做全流量排查。
