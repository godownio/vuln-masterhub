---
id: code-analysis-reverse-windows-machineguid-md5-aes-cfb-payload-binding
title: 恶意载荷机器绑定：MachineGuid 的 MD5 作 AES-CFB IV，配置/载荷 MD5 完整性校验
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: machineguid-md5-aes-cfb-payload-binding
tags:
- reverse
- malware
- aes-cfb
- machineguid
- md5
- config-decrypt
- payload-binding
- anti-analysis
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T07:52:17+08:00'
  notes: 已对照原文与21张图核对：MD5完整性校验、AES-CFB解配置、DAT前4字节目标标记、MachineGuid MD5作绑定IV重加密均一致；注意原文配置dump的aes_iv(9aaacddc...)与CyberChef截图IV(d4b7cf...)不一致，卡片沿用截图值；PoC未执行
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-machineguid-md5-aes-cfb-payload-binding/
draft: false
kb_aliases:
- MachineGuid IV
- 机器 GUID 绑定
- AES-CFB 载荷
- DAT 载荷解密
- 配置 MD5 校验
---

## 一句话结论

样本用硬编码 key 与配置中的 IV 以 AES-CFB 解密配置和 DAT 载荷，配置段与载荷分别用 MD5 与硬编码哈希比对保证完整性；解密后读取注册表 `SOFTWARE\Microsoft\Cryptography\MachineGuid` 的 MD5 作为新 IV 重新加密载荷，使其只能在当前主机解密，并用 DAT 前 4 字节标记“特定目标”载荷。

## 原理

- **配置完整性 + 加密**：样本内有两段密文，先计算每段 MD5 与硬编码值（原文 `FE93E8E1C5C3032A26D783A78A820587`、`1E8EE70F02D60E389D8F721E8CE6DF1F`）比对，校验通过后再 AES-CFB 解密；解出的配置含 `sbiedll.dat`、`--type`、载荷偏移/大小、AES key/IV、载荷 MD5、`enable_delete_dat_file`/`enable_unlink_from_peb`/`enable_terminate_process` 等开关。
- **AES-CFB 的复现条件**：CFB 是流式模式，不需要 padding；只要 key/IV 与分段偏移正确，CyberChef/OpenSSL 就能直接解出明文。原文用 key `489b0fb53b49a8635dde3fdf6d68b487`、IV `d4b7cf998899fe0e4735859b996b1330` 解出以 `MZ`/`PE` 开头的载荷（CyberChef 输出可见 “This program cannot be run in DOS mode”）。
- **DAT 载荷读取与目标标记**：`NtReadFile` 把 `sbiedll.dat` 读入当前进程堆；检查前 4 个字节——非零表示该 DAT 是投递给特定目标的机器绑定载荷，为零则按通用载荷处理；随后从第 5 个字节（偏移 4）开始按配置的 key/IV 解密。
- **MachineGuid 绑定**：读取 `SOFTWARE\Microsoft\Cryptography\MachineGuid`（`RegOpenKeyExA`/`RegQueryValueExA`），对取到的 GUID 数据计算 MD5，把该 MD5 作为 AES-CFB 的 IV，用同一 AES key 重新加密解密后的载荷。这样 DAT 文件换了机器就解不出正确载荷——IV 不同，CFB 首块及后续全部错位。
- **为什么有效**：即使分析者从样本中提取到 AES key 和配置 IV，也无法在另一台机器上还原“绑定后”的载荷；MD5 完整性校验又让直接改配置/载荷容易失败。代价是样本必须在本机读取 MachineGuid，留下了可检测的注册表访问行为。
- **与“首次解密 IV”的区别**：配置里有独立的 AES IV 用于 DAT 初始解密；MachineGuid 的 MD5 是**重加密/绑定**时使用的新 IV，两者不要混用。

## 触发条件

- Windows 环境；样本能读取 `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`（普通用户一般可读）。
- 样本自带加密配置与 DAT 载荷文件；配置中的 key/IV/偏移/大小可提取或调试读取。
- 使用 AES-CFB（或其他流式模式）且 IV 可控；载荷首 4 字节作为目标标记的约定存在。
- 分析者需要离线复现时，必须知道原始主机的 MachineGuid 或改掉绑定逻辑。

## 利用步骤

> 本卡为逆向分析/复现视角；“利用步骤”即提取与解密流程。

1. 定位配置密文与两处 MD5 比较，记录硬编码 MD5 值；用 MD5 校验确认配置段边界。
2. 从解密后的配置或样本常量中提取 AES key、IV、载荷偏移/大小、载荷 MD5 与各种开关。
3. 用 CyberChef/Python 按 AES-CFB 解密配置段；在输出中查找 `sbiedll.dat`、`--type`、key/IV、偏移等字段。
4. 读取 DAT 文件前 4 字节判断是否为目标特定载荷；从第 5 字节开始用配置的 key/IV 解密，检查是否得到 `MZ`/`PE`。
5. 读取本机 `MachineGuid` 并计算 MD5，作为 IV 复现“重加密/绑定”过程；若要分析绑定后的载荷，使用原始机器或 patch 掉 MachineGuid 读取/IV 替换。
6. 对解出的 PE 做反射加载分析/内存 dump；注意样本可能删除 DAT、从 PEB 断链、终止进程（配置开关）。

## PoC

AES-CFB 解密 DAT（Python `cryptography`，偏移按原文从第 5 字节开始）：

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = bytes.fromhex("489b0fb53b49a8635dde3fdf6d68b487")
iv  = bytes.fromhex("d4b7cf998899fe0e4735859b996b1330")
data = open("sbiedll.dat", "rb").read()

# 前 4 字节为目标标记；原文从第 5 字节开始解密
ct = data[4:]
pt = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor().update(ct)
open("payload.bin", "wb").write(pt)
print(pt[:2])  # b'MZ' 表示解出 PE
```

MachineGuid 读取与 MD5（绑定 IV）：

```python
import hashlib, winreg

with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
    guid, _ = winreg.QueryValueEx(k, "MachineGuid")
iv_bind = hashlib.md5(guid.encode()).digest()
print(guid, iv_bind.hex())
```

## 变体与关联

- **变体**：IV 可来自 MachineGuid 的 MD5、卷序列号、网卡 MAC、用户名/主机名组合；算法可换 AES-CBC（需 padding）、ChaCha20、RC4；完整性可用 MD5/SHA1/SHA256/HMAC；目标标记可放在文件头、配置字段或注册表。
- **关联卡片**：[[code-analysis-reverse-windows-quasar-rat-aes256-config-decrypt]]（Quasar 的 PBKDF2 + AES-256-CBC 配置解密，无机器绑定）；[[code-analysis-reverse-windows-aes-config-capa-xref-key-cyberchef]]（capa/CyberChef 静态提取 AES 配置）；[[code-analysis-reverse-windows-blacknet-config-aes-pbkdf2-extract]]（PBKDF2+AES-CBC 配置）；[[defense-forensics-fake-v2ray-embedded-rc4-dll-extract]]（同目录加密载荷提取，不同算法）。
- **区分**：本卡的重点是“MachineGuid 派生 IV 做主机绑定”，不是通用配置解密。

## 检测与防御

- **动态检测**：监控非系统进程对 `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` 的读取；监控 `NtReadFile` 读取同目录 DAT 后立刻做 AES/哈希运算的行为。
- **静态检测**：搜索 AES key/IV 常量、MD5 常量与 `RegQueryValueExA("MachineGuid")` 的交叉引用；识别“读注册表→MD5→AES IV”的数据流。
- **取证**：在原始主机上保留 MachineGuid 或内存镜像，才能在离线环境复现绑定载荷；否则需 patch IV/跳过绑定。
- **防御**：EDR 对 MachineGuid 读取与反射加载做关联告警；限制未知样本读取注册表与执行内存 PE；对同目录 DAT 文件的异常读取做监控。
- **局限**：绑定只防“换机解密”，不防内存 dump/动态调试；分析者可在绑定完成后从内存直接 dump 明文载荷。
