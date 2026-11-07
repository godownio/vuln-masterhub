---
id: code-analysis-reverse-windows-api-hook-hidden-aes-branch
title: Windows API inline hook 隐藏校验分支：MessageBoxA 被重定向到 AES 校验
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: windows-api-inline-hook-hidden-validation
aliases:
- API inline hook
- MessageBoxA hook
- 隐藏校验分支
- Illusion
- 表面 RC4 实际 AES
tags:
- reverse
- windows
- api-hook
- inline-hook
- aes
- anti-analysis
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:13:39+08:00'
  notes: 已对照原文与图02核对：VirtualProtect 改写 MessageBoxA 入口 0xE 字节并跳转 sub_10F0、hook 内 4 个 DWORD（873608210×3、559105345）小端拼出 1234123412341234AES!、AES-128-ECB 解密 32 字节密文得 R3a1_w0rld_M47ters、主逻辑 RC4 nev_gona_give_up 为 fake 均一致。未验证点：PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

程序主逻辑看起来是 RC4 校验（还解出一个 fake flag），但初始化时用 `VirtualProtect` 把 `user32!MessageBoxA` 的前 14 字节改写成跳转到自定义函数的 inline hook；真正的 flag 校验藏在 hook 函数里，用硬编码 DWORD 拼出 AES key 做 AES-128-ECB 解密，恢复该 key 即可拿到真 flag。

## 原理

- 程序启动时调用 `sub_1000`：通过 PEB/`GetModuleHandleA("user32.dll")`/`GetProcAddress` 找到 `MessageBoxA`，用 `VirtualProtect(..., 0xE, PAGE_EXECUTE_READWRITE)` 修改其入口，保存原始 14 字节，再写入跳转到 `sub_10F0` 的 stub。
- 之后任何对 `MessageBoxA` 的调用都会进入 `sub_10F0`，执行作者自定义的校验逻辑；校验完成后它恢复原始字节并调用真正的 `MessageBoxA`。
- 主函数里的 RC4 逻辑（key `nev_gona_give_up`）只是诱饵，解出的 `nev_gona_letydown` 是 fake flag；真正的分支在 hook 函数中。
- `sub_10F0` 把 4 个 DWORD `873608210, 873608210, 873608210, 559105345` 按小端拼成 16 字节 key：`12 34 12 34 ... 41 45 53 21`，即 `1234123412341234AES!`；再用 AES-128-ECB 解密 32 字节硬编码密文，去掉 PKCS#7 padding 得到真 flag。
- 该手法利用“API 入口可写 + 调用点被劫持”隐藏真实控制流；静态看导入表/主函数会误判为 RC4，只有跟进 hook 目标才能看到 AES 分支。

## 触发条件

- 样本在初始化阶段解析并改写系统 API（`MessageBoxA`、`GetProcAddress`、`VirtualProtect` 等）的入口。
- 主函数中存在明显但“过于简单”的校验/假 flag，作为诱饵。
- hook 目标函数包含另一套加密/校验逻辑。
- 分析者能定位 hook stub、恢复原始字节或直接调用 hook 目标。

## 利用步骤

1. 在 IDA 中定位 `VirtualProtect`、`GetProcAddress`、`MessageBoxA` 相关调用，确认入口被改写。
2. 跟进写入的跳转 stub，找到 hook 目标函数（如 `sub_10F0`）。
3. 在 hook 目标中提取硬编码 key 材料（DWORD 数组、字符串、常量）与密文。
4. 按字节序（示例小端）拼接 key；识别 AES 模式（ECB/CBC）与 padding。
5. 用 AES 解密硬编码密文，去 padding，得到 flag；用主函数中的 RC4 结果做对照，确认其为 fake。
6. 若 hook 在运行时才写入，可动态断在 `VirtualProtect` 后 dump 被修改的 API 入口。

## PoC

```python
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

dwords = [873608210, 873608210, 873608210, 559105345]
key = b"".join(struct.pack("<I", d) for d in dwords)
print(key)  # b'1234123412341234AES!'

ct = bytes.fromhex(
    "f27b7e75b45c08fa193c8a4a04f81f67"
    "1b059ce72740786d28f6a8b806c6c551"
)
pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
print(unpad(pt, 16).decode())
```

## 变体与关联

- 变体：hook `MessageBoxA` 之外的 API（`GetProcAddress`、`IsDebuggerPresent`、`CryptDecrypt`），或使用 IAT hook 而非 inline hook。
- 变体：key 由字符串、资源、注册表或环境变量派生；密文可能分片存放。
- 变体：主函数诱饵可能是 RC4、Base64、简单异或，真逻辑在 hook/异常处理/线程回调中。
- 关联：[[code-analysis-reverse-windows-x86-inline-hook-packet-intercept]]（inline hook 拦截）、[[ctf-reverse-predictable-score-derived-aes-key-iv]]（硬编码 AES key）、[[code-analysis-reverse-windows-cng-bcrypt-rc4-md5]]（Windows 加密 API 定位）。

## 检测与防御

- 检测：监控 `VirtualProtect` 对 `user32.dll`/`kernel32.dll` 代码段的 RWX 修改；扫描 API 入口是否被 jmp patch；对比磁盘文件与内存中的代码段。
- 防御：启用 CFG/CET、代码完整性保护（HVCI）、EDR 的 API hook 检测；对敏感进程做内存完整性校验。
- 响应：确认 inline hook 后 dump 被修改区域，恢复原始字节，提取 hook 目标中的密钥/密文。
