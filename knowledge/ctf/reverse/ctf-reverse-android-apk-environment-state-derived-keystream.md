---
id: ctf-reverse-android-apk-environment-state-derived-keystream
title: APK 环境状态绑定校验：dex/签名哈希 + 资源 ID + 自定义 chunk 折叠为 VM keystream
type: scenario
domain: ctf
path: ctf/reverse
technique: android-apk-environment-state-derived-keystream
aliases:
- 折叠回声
- EchoFold
- EchoGate
- FirstEchoCodec
- TraceRecorder
- EchoFoldPulse
- EFVM
tags:
- ctf
- reverse
- android
- apk
- dex
- signature
- resource-id
- vm
- keystream
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:24:52+08:00'
  notes: 已对照原文核对：FirstEchoCodec 假 flag、EchoGate.verify 读取 classes.dex SHA-256、签名证书 SHA-256、TraceRecorder.TRACE 11 23 7a 42 51 66、R$styleable.EchoFoldPulse 32 个 0x7f010000..0x7f01001f、ECH0 chunk 交给 EFVM 生成 keystream、flag f0lded_echo_is_a_state_not_a_string 与 dex hash c82404... 均与卡片一致；原文未展开 VM 字节码/解释器，卡片已标 confidence medium 且 PoC 只覆盖 key material 构造。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

`EchoGate.verify()` 不比较静态字符串，而是把 `classes.dex` 的 SHA-256、APK 签名证书 SHA-256、`TraceRecorder.TRACE`、`R$styleable.EchoFoldPulse` 的 32 个资源 ID 拼成 VM 输入，用 `assets/sleep_loop.webp` 中 `ECH0` chunk 里的自定义 VM 生成 keystream，再 XOR 密文得到 flag body；因此 flag 是 APK 环境状态的函数，换包/重编译就算不出。

## 原理

- **第一层假 flag**：dex 明文 `ISCC{this_is_only_the_first_echo}` 和 `FirstEchoCodec.check()` 是筛选器；真正校验在 `EchoGate.verify()`。只做 `strings` 会停在假答案。
- **环境 key material**：`sha256(classes.dex)` + `sha256(APK 签名证书)` + `TraceRecorder.snapshot()`（静态数组 `11 23 7a 42 51 66`）+ `resourceKey()`（32 个资源 ID `0x7f010000..0x7f01001f` 的小端字节）。
- **VM**：`ECH0` chunk 是 EFVM 字节码；`runVm(ech0, vmInput, flagLength)` 输出 keystream；`plain = cipher XOR stream`；再与输入 body 比较。
- **为什么环境绑定**：dex hash 随代码变化，签名 hash 随重签名变化，资源 ID 随 aapt/aapt2 分配变化；三者任一变化，VM 输入变，keystream 变，flag 对不上。
- **资源 ID 布局**：Android 资源 ID 为 `0xPPTTEEEE`；本题从 `0x7f010000` 起连续 32 个，`PP=0x7f`、`TT=0x01`、`EEEE=0x0000..0x001f`。
- **本题结果**：flag body 为 `f0lded_echo_is_a_state_not_a_string`，flag 为 `ISCC{f0lded_echo_is_a_state_not_a_string}`；`classes.dex` SHA-256 为 `c82404bedd319ef962e9c114dcec9566265c140d621319f795c14a0a12d2df77`。

## 触发条件

- APK 无 native 库，核心校验在 DEX；存在自定义 VM/解释器类。
- 校验读取 APK 自身文件/签名/资源表，而不是只读输入。
- assets 中有非标准容器/自定义 chunk。
- 能拿到原始 APK（不能重打包/重编译）。

## 利用步骤

1. jadx 找 `verify`/`check`，区分假 flag 校验与真正校验；看它读取哪些环境值。
2. 计算 `sha256(classes.dex)`；从 APK 的 `META-INF/*.RSA` 取证书 DER 算 SHA-256（或从 jadx 的签名信息获取）。
3. 从 DEX 静态初始化恢复 `TraceRecorder.TRACE` 字节；从 `R$styleable` 恢复 32 个资源 ID，按小端拼字节。
4. 从 WebP 取 `ECH0` chunk；按 VM 的 opcode 表/解释器复刻 `runVm`，输入为上述 key material。
5. 用 VM 输出 XOR 密文，得到 flag body；或直接 patch `verify` 打印中间 plain。
6. 用原 APK 复算校验；重打包会改变 dex hash/签名/资源 ID，需同步所有输入。

## PoC

```python
import hashlib
import struct
import zipfile
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

apk = "EchoFold.apk"
with zipfile.ZipFile(apk) as z:
    dex = z.read("classes.dex")
    webp = z.read("assets/sleep_loop.webp")
    rsa = z.read("META-INF/ECHOFOLD.RSA")

dex_hash = hashlib.sha256(dex).digest()
cert = pkcs7.load_der_pkcs7_certificates(rsa)[0]
cert_hash = hashlib.sha256(cert.public_bytes(Encoding.DER)).digest()
trace = bytes([0x11, 0x23, 0x7a, 0x42, 0x51, 0x66])
pulse = b"".join(struct.pack("<I", 0x7f010000 + i) for i in range(32))

key_material = dex_hash + cert_hash + trace + pulse
print("dex sha256 =", dex_hash.hex())
print("key material =", key_material.hex())

# ECH0 提取见 [[ctf-forensics-webp-riff-custom-chunk-ech0-extraction]]
# stream = runVm(ech0, key_material, flag_len)
# plain = cipher ^ stream
```

VM 字节码与解释器未在原文完整展开，PoC 只覆盖环境 key material 的构造；置信度标 medium。

## 变体与关联

- **环境输入变体**：`PackageInfo` 版本号、安装时间、设备 ID、资源字符串、so hash、DEX 校验和、资源 ID、Trace/埋点数组。
- **VM 变体**：简单 XOR/RC4/自定义字节码；先找 opcode dispatch 和 keystream 生成循环。
- **关联卡片**：[[ctf-forensics-webp-riff-custom-chunk-ech0-extraction]]（ECH0 提取）、[[ctf-reverse-android-arm64-jni-unicorn-offline-oracle]]（离线 oracle）、[[ctf-reverse-apk-signature-sha1-xor-key-hidden-flag]]（签名参与密钥）。
- **边界**：重打包/重编译会改变环境值；若 VM 依赖未公开的资源 ID 分配，必须用原包；只解出 keystream 但不知道密文位置仍不完整。

## 检测与防御

- **防御视角**：环境绑定只能提高重打包成本，不能替代服务端校验；关键 flag 不要由客户端环境派生。
- **检测信号**：DEX 中读取自身 APK/签名/资源 ID + 自定义 VM；assets 中未知 chunk；校验函数同时读取多个环境源。
- **CTF 逆向**：先找假 flag，再找真正 verify；把所有环境输入列全，缺一不可。
