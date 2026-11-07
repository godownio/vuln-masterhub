---
id: defense-forensics-fake-v2ray-embedded-rc4-dll-extract
title: 伪装 v2ray 的恶意程序：RC4 解密同目录载荷提取 DLL 并还原文件加密链
type: scenario
domain: defense
path: defense/forensics
technique: fake-v2ray-embedded-rc4-dll-extract
aliases:
- 伪装 v2rayN
- 假 v2ray 恶意样本
- RC4 内嵌 DLL
- FtFiles.edb
- proxy 目录恶意程序
tags:
- defense
- forensics
- malware
- rc4
- dll
- payload
- v2ray
- file-encryption
- pe
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:30:27+08:00'
  notes: 已对照原文图52/53/55/56核对：proxy目录、fopen RnRGaWxlcy5lZGIiL、前16字符Base64为FtFiles.edb、RC4 KSA/PRGA、PE64 DLL基址0x180000000/入口0x180002730、二层AES key cgDSb6VOegeF7EuW与sub_180001920调用点均一致；无CVE、无sources/source_url；未复跑样本。疑点：图53 IDA中key名显示为截断的a1njc2ntq2mzc0n，与原文答案1Njc2NTQ2Mzc0NTc大小写/长度不完全一致，未能实跑验证。
---

## 一句话结论

样本把自身伪装成 v2ray（可执行文件位于 `proxy` 目录），主程序读取同目录下的加密文件 `RnRGaWxlcy5lZGIiL`（前 16 个字符是 `FtFiles.edb` 的 Base64），用硬编码 RC4 key `1Njc2NTQ2Mzc0NTc` 解密，得到的是一份 PE64 DLL（镜像基址 `0x180000000`、入口 `0x180002730`）；该 DLL 再以 `cgDSb6VOegeF7EuW` 为密钥、用魔改 AES 加密 `download` 目录中的文件。

## 原理

- 伪装层：可执行文件放在名为 `proxy` 的目录，命名与功能模仿 v2rayN 等代理工具；主函数先 `GetConsoleWindow` + `ShowWindow(SW_HIDE)` 隐藏窗口，再读取同目录载荷，行为与正常代理程序不符。
- 载荷读取：`fopen(L"RnRGaWxlcy5lZGIiL", "rb")` → `fseek/ftell` → `malloc` → `fread`；文件名本身是编码后的字符串（前 16 个字符 `RnRGaWxlcy5lZGI=` Base64 解码为 `FtFiles.edb`），用于躲避基于文件名的检测。
- RC4 识别：解密函数里出现 256 字节 S 盒初始化、`j = (j + S[i] + key[i % keylen]) % 256`、交换 `S[i]/S[j]`、输出 `S[(S[i]+S[j]) % 256]`，对数据逐字节异或；这是标准 RC4 KSA+PRGA。key 以参数或全局常量传入，案例为 ASCII `1Njc2NTQ2Mzc0NTc`。
- 解密结果校验：输出以 `MZ` 开头，`e_lfanew` 指向 `PE\0\0`；DIE 识别为 PE64 DLL（AMD64、Microsoft Visual C++、链接器 14.36），镜像基址 `0x180000000`，入口 `0x180002730`。
- 二层危害：DLL 被加载后遍历 `download` 目录，对文件调用 `sub_180001920`；调用处传入 key `cgDSb6VOegeF7EuW` 和 `unk_180025A70`，内部使用 AES-CBC，且密钥扩展对轮密钥做了逐块交换（见关联卡），最终把用户下载目录中的文件加密。
- 取证价值：主程序本身只是加载器；真正的文件加密逻辑在解密后的 DLL 中，因此必须先静态提取并解密载荷，才能恢复算法、密钥与 IV。

## 触发条件

- 样本为 PE 加载器，同目录带有非 PE 的加密数据文件；文件名或字符串经过 Base64 或其它编码。
- 解密函数具备 RC4 的 256 字节状态数组与取模运算；key 硬编码或在加载时派生。
- 解密结果可写成文件并用 PE 工具解析（MZ/PE 头、节表、导出表）。
- 第二阶段 DLL 负责文件遍历/加密，能从其导入表、字符串或调用点定位目标目录与密钥。

## 利用步骤

1. 静态检查样本目录：确认伪装对象（`proxy`、v2ray 命名）、同目录数据文件、导入函数（`fopen/fread/malloc`、`LoadLibrary`/`GetProcAddress`）。
2. 在 IDA 中跟主函数：记录 `fopen` 的文件名、`fread` 长度、解密函数地址与 key 参数；确认 RC4 KSA/PRGA。
3. 提取加密文件字节，用 RC4 解密；写出后用 `file`/DIE/PE-bear 检查 `MZ`、`PE`、机器类型与入口点。
4. 将 DLL 载入 IDA，定位 DllMain/导出函数；查找 `FindFirstFile/FindNextFile`、文件读写、AES 常量与 key/IV 引用。
5. 恢复第二层算法参数（案例 key `cgDSb6VOegeF7EuW`、逐块轮密钥交换规则），对 `download` 目录中被加密文件离线解密。
6. 交叉验证：解密后的文件头/扩展名、原始文件大小、样本日志或配置中的路径。

## PoC

```python
def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)

blob = open("RnRGaWxlcy5lZGIiL", "rb").read()
pe = rc4(blob, b"1Njc2NTQ2Mzc0NTc")
open("stage2.dll", "wb").write(pe)
assert pe[:2] == b"MZ"
```

本卡不执行样本；解密出的 DLL 仅用于静态分析。

## 变体与关联

- 载荷可能是 shellcode、DLL、EXE 或加密配置；RC4 可能被改成自定义 KSA/PRGA 轮数，需按反编译逻辑复现。
- key 可能来自机器 GUID、注册表、argv、环境变量或另一层解密；案例为硬编码 ASCII。
- 文件名编码可能用 Base64、反转、异或或自定义表；先看字符集与填充。
- 关联：[[ctf-reverse-aes-cbc-roundkey-swap-per-block]]（DLL 使用的逐块轮密钥交换 AES）、[[defense-forensics-cryptoapi-aes256-file-encrypt-key-iv-recovery]]（Windows 文件加密样本的 key/IV 恢复）、[[code-analysis-reverse-windows-dridex-rc4-base64-aplib-shellcode-extract]]（RC4+Base64 载荷提取）。
- 边界：若载荷在内存中解密且不落盘，或 key 由服务端下发，静态提取会失败，需要动态 dump 或内存取证。

## 检测与防御

- 检测：目录中出现“代理工具 + 非 PE 数据文件 + 隐藏窗口”组合；导入 `fopen/malloc/LoadLibrary` 且字符串含 Base64 文件名；RC4 的 256 字节状态与取模循环；DLL 遍历 `download` 并批量写文件。
- 终端：监控伪装代理进程加载同目录 DLL、批量改写用户下载目录、写入加密扩展名；限制普通用户对 `proxy` 目录的写权限。
- 防御：从官方渠道安装代理工具并校验签名/哈希；应用白名单；备份下载目录；对加密文件保留原始副本以便恢复。
- 取证：保留样本、同目录载荷、内存镜像与文件系统；先提取 stage2 再分析密钥，避免直接在受害机运行。
