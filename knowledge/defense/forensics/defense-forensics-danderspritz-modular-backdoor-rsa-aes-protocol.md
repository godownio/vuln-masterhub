---
id: defense-forensics-danderspritz-modular-backdoor-rsa-aes-protocol
title: DanderSpritz 模块化后门通信协议：内置 RSA 公钥校验 + RSA 封装 AES 会话密钥 + 模块下发解密
type: scenario
domain: defense
path: defense/forensics
technique: danderspritz-rsa-aes-module-protocol
aliases:
- DanderSpritz 通信协议
- PC_Level3_exe.configured
- Dsz_Implant_Pc.dll
- NSA 模块化后门
- RSA 公钥内置
- 0x8E3071AB 校验
- AES 会话密钥交换
- 模块化后门流量解密
tags:
- forensics
- traffic-analysis
- malware-analysis
- windows
- danderspritz
- nsa
- rsa
- aes
- c2
- modular-backdoor
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V198
  verified_at: '2026-11-06T22:41:29+08:00'
  notes: 已对照原文及31张截图核对：256字节RSA握手、00 01 FF...00填充、12字节载荷0x0002/0x8E3071AB/长度<=0x400、SHA1派生AES密钥、0x30载荷RSA封装、#序号+zero-run压缩模块下发均与截图一致；未给出可执行完整解密脚本
---

## 一句话结论

DanderSpritz 的 `PC_Level3_exe.configured` 木马在二进制中内置 RSA 公钥：上线后先接收 256 字节 RSA 密文，解密后按 PKCS#1 v1.5 结构（`00 01 FF...FF 00`）和 12 字节有效载荷中的 `0x0002`、校验值、固定魔术 `0x8E3071AB` 验证对端持有配套私钥；校验通过后用系统 API 采集熵、经 SHA1 派生 AES 密钥，把 16 字节密钥放进 0x30 字节载荷再用 RSA 加密回传，之后所有通信（包括模块 PE 下发）都用该 AES 密钥加密。掌握公钥、私钥或从内存提取 AES 密钥即可离线还原流量并提取模块。

## 原理

- **内置 RSA 公钥**：`Keys` 目录包含 `private_key.bin`/`public_key.bin`；生成的木马二进制中直接嵌入 `public_key.bin` 内容（约 0x204 字节）。控制端持有私钥，木马持有公钥，形成单向密钥交换：只有控制端能解开木马用公钥加密的会话密钥。
- **握手第一步是密钥校验**：木马建立连接后先 `RecvData` 256 字节，用内置公钥做 RSA 解密。解密结果需符合 PKCS#1 v1.5 填充：首字节 `0x00`、第二字节 `0x01`、随后大量 `0xFF`、最后一个 `0xFF` 后为 `0x00`；`0x00` 之后是有效数据。代码还会做字节序反转（`FUN_ReverseInt`），说明网络字节序与大端/小端转换需按实现处理。
- **12 字节有效载荷的魔术校验**：有效长度必须为 12；前两字节为 `0x0002`；接下来两字节为校验值且 `>= 0x0003`；再四字节固定为 `0x8E3071AB`；最后两字节为下一段数据的长度（代码检查 `<= 0x400`）。这套结构既验证 RSA 私钥配套，也防止把随机数据误当握手包；`0x8E3071AB` 可作为流量/样本指纹。
- **AES 密钥的生成**：木马调用 `GetCursorPos`、`GetThreadTimes`、`GetDiskFreeSpaceExW`、`GlobalMemoryStatus`、`GetTickCount`、`QueryPerformanceCounter`、`GetSystemTimeAsFileTime`、`GetCurrentProcessId`/`GetCurrentThreadId` 等采集随时间/环境变化的数据，反复调用 SHA1（每次 0x28 字节）混合，最后生成 16 字节 AES 密钥。这不是密码学安全的随机数，但每个会话不同，足以避免固定密钥特征。
- **AES 密钥的 RSA 封装**：把 16 字节 AES 密钥放进 0x30 字节有效载荷，前面填充随机数据，整体构成 256 字节后再用 RSA 公钥加密，`SendData` 发送 0x100 字节。控制端用私钥解出 AES 密钥，双方后续用 AES 通信。代码还检查加密后长度字段 `HIWORD==2`、`(BYTE)>=3`，与 PKCS#1 结构对应。
- **模块下发**：控制端用 AES 加密发送模块数据：第一段是模块导出函数编号，以 `#` 开头（如 `#1`）；第二段是压缩后的 PE 文件内容，压缩算法本质是压缩连续的 `00` 字节（zero-run compression）；木马解压得到 `Dsz_Implant_Pc.dll` 并加载。`Dsz_Implant_Pc.dll` 沿用同一 AES 密钥，但通信数据的填充方式与 `PC_Level3` 不同。
- **多层协议对比**：`PC_Level3` 为纯 AES；`Dsz_Implant_Pc.dll` 为 AES + 压缩；事件中的 `New-Dsz-Implant` 为 TLS1.2 + AES + 压缩；`eHome_0cx` 为 TLS + XX 算法；`Back_Eleven` 为 TLS1.3 + AES。逐层剥开后才能看到模块明文 PE。
- **解密可行性**：如果拿到控制端私钥（`private_key.bin`），可离线解出每个会话的 AES 密钥并解密全部流量；如果只有木马样本/内存，可从进程内存中提取已生成的 AES 密钥（`sub_402810(a1, aeskey, 16)` 设置的上下文），再解密模块下发。文章即通过构建专用解密程序还原了通信内容并提取 20 余个模块。

## 触发条件

- 捕获到 `PC_Level3_exe.configured`/Dsz 系列木马与控制端之间的 TCP 流量（通常为自定义端口，非 TLS 或外层已有 TLS 需先剥离）。
- 拥有以下任一条件：控制端 RSA 私钥、木马进程内存中的 AES 密钥、或能在调试器中截获 `sub_402810` 设置的密钥。
- 流量包含完整握手（首包 256 字节 RSA 密文 + 后续 AES 数据）；只有 AES 密文而无握手时，需要已知/暴力 AES 密钥。
- 分析环境具备 RSA 解密（对应填充模式）与 AES 解密能力；模块数据还需实现 zero-run 解压。

## 利用步骤

1. **定位样本与公钥**：在木马二进制中搜索 `public_key.bin` 内容（RSA 公钥结构），确认 `Keys` 目录与 `PC_Level3_exe.configured` 的对应关系。
2. **抓取握手**：从 PCAP 提取受害端发送的首个 256 字节数据包，作为 RSA 密文；若为多段 TCP，先重组。
3. **RSA 解密与校验**：用私钥（或已知公钥对应的私钥）解密，检查 `00 01 FF...FF 00` 填充、12 字节有效载荷、`0x0002`、校验值、`0x8E3071AB`、下一段长度；不匹配说明私钥不对或包序错误。
4. **提取 AES 密钥**：解密控制端后续回传/木马发送的 0x100 字节 RSA 包，取 0x30 字节有效载荷中的 16 字节 AES 密钥；或在调试器中于 `sub_402810(a1, aeskey, 16)` 处下断读取。
5. **AES 解密流量**：按木马实现的 AES 模式/填充解密后续数据；注意 `Dsz_Implant_Pc.dll` 与 `PC_Level3` 的填充方式不同，需分别处理。
6. **识别模块段**：解密后第一段是 `#<导出序号>`，第二段是 zero-run 压缩的 PE；按实现解压，校验 `MZ`/`PE` 头。
7. **提取模块**：保存解压后的 DLL，计算 MD5/导入表/导出表，与已知 DanderSpritz 模块列表比对；文章提取的 25 个模块包括 `Audit_Target_Vista.dll`、`Cd_Target.dll`、`Dir_Target.dll`、`PasswordDump_Target.dll`、`ProcessInfo_Target.dll`、`RegistryQuery_Target.dll`、`Scheduler_Target.dll`、`Services_Target.dll`、`Time_Target.dll` 等。

## PoC

握手包校验的伪代码（按原文反编译逻辑还原）：

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

key = RSA.import_key(open("private_key.bin", "rb").read())
cipher = PKCS1_v1_5.new(key)
plain = cipher.decrypt(first_256_bytes, sentinel=None)
if plain is None:
    raise SystemExit("RSA padding/private key mismatch")

# PKCS#1 v1.5: 00 01 FF...FF 00 <payload>
assert plain[0] == 0x00 and plain[1] == 0x01
sep = plain.index(b"\x00", 2)
payload = plain[sep + 1:]
assert len(payload) == 12
assert payload[0:2] == b"\x00\x02"
assert int.from_bytes(payload[2:4], "big") >= 3
assert payload[4:8] == bytes.fromhex("8e3071ab")
next_len = int.from_bytes(payload[10:12], "big")
print("next segment length:", next_len)
```

AES 密钥提取（调试器/内存）：

```text
断点：sub_402810(a1, aeskey, 16)
读取：aeskey 指向的 16 字节
后续：AES 解密模块数据 → 第一段 "#<ordinal>" → 第二段 zero-run 解压 → PE
```

文章未给出完整解密脚本；上述校验逻辑按截图中的 `FUN_RSA_dec`/`FUN_ReverseInt`/`0x8E3071AB` 比较还原，未在本库执行。

## 变体与关联

- **外层 TLS 变体**：事件中的 `New-Dsz-Implant` 在 AES+压缩外再套 TLS1.2，`Back_Eleven` 套 TLS1.3；需先在 TLS 层解密（若有会话密钥/私钥），再处理内层。
- **密钥来源变体**：RSA 私钥可能只在控制端；木马端只有公钥。没有私钥时，优先从内存提取 AES 密钥，或 hook `sub_402810`/AES 初始化函数。
- **压缩算法变体**：zero-run 压缩只压缩连续 `00`，实现简单；不同模块包可能使用不同压缩器（如 zlib），需按模块头/熵判断。
- **模块协议变体**：导出序号可能以 `#` 开头，也可能是纯数字；第一段与第二段可能合并在同一 AES 明文块中，需按长度字段切分。
- **同源平台**：DanderSpritz 与 WannaCry/永恒之蓝同属 NSA 武器生态；模块列表中的 `Mcl_*`、`*_Target.dll` 命名可作为家族/平台指纹。
- 关联：[[pentest-c2-danderspritz-modular-loader-export-ordinal-section-map]]（本协议的模块加载侧）、[[defense-forensics-winos4-c2-frame-xor-decrypt]]（另一种远控二进制帧解密）、[[defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt]]（长度+nonce+GCM 帧）、[[defense-forensics-sm4-c2-traffic-seed-prng-key-decrypt]]（国密 C2 流量解密）。

## 检测与防御

- **流量检测**：匹配首包 256 字节 RSA 密文、PKCS#1 填充特征、12 字节有效载荷中的 `0x8E3071AB`；对非 TLS 自定义 TCP 会话中出现 `#<数字>` 短段 + 高熵 PE 数据的组合告警。
- **主机检测**：监控进程调用 `GetCursorPos`/`GetThreadTimes`/`GetDiskFreeSpaceExW`/`GlobalMemoryStatus`/`QueryPerformanceCounter` 等组合采集熵后接 SHA1/AES 初始化的行为；监控 `NtCreateSection`+`NtMapViewOfSection` 映射无文件背书的 PE；检查内存中已解压的 `*_Target.dll`/`Mcl_*` 模块。
- **取证要点**：优先保存完整握手与会话、进程内存（AES 密钥）、模块解压后的 PE；用 `private_key.bin` 离线解密，或从内存提取密钥；把模块 MD5 与已知 DanderSpritz 模块库比对。
- **防御**：限制非业务进程的原始 TCP 出站；对内存中无文件背书的 PE 映射做 EDR 告警；及时更新 AV/EDR 对 DanderSpritz/Dsz 家族的签名；对关键主机做内存与模块完整性巡检。
