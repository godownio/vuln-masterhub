---
id: code-analysis-reverse-windows-ransomware-large-file-intermittent-encryption-three-128kb
title: 勒索软件大文件间歇加密：首/中/尾各 128KB AES-CBC 读改写，留下三块高熵密文
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: ransomware-large-file-intermittent-encryption-three-128kb
tags:
- windows
- ransomware
- intermittent-encryption
- partial-encryption
- aes-cbc
- forensic-artifact
- malware-analysis
- file-format
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V280
  verified_at: '2026-11-08T02:16:06+08:00'
  notes: 已对照原文与 img19/22 核对：smethod_4(path,131072,0,length/2,length-131072) 三位置各 128KB、smethod_5 AES-256-CBC 无填充、段长不变、RSA 封装附尾、==524288 两分支均不命中均符；修正 PoC 中 AES 对象复用导致 CBC 链连续的问题（改为每段新建 AES 对象），未执行样本
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-ransomware-large-file-intermittent-encryption-three-128kb/
draft: false
kb_aliases:
- 间歇加密
- 局部加密
- 分块加密
- 首中尾 128KB 加密
- partial encryption
- intermittent encryption
- 高熵块取证
- smethod_4
---

## 一句话结论

CryptNet 对大于 524288 字节的文件不做全量加密，而是调用 `smethod_4(file, 131072, 0, length/2, length-131072)`，在文件开头、中间、末尾三个偏移各读取 128KB，用该文件随机 key/IV 做 AES-256-CBC 加密后写回原位置，最后追加 RSA 封装块。文件大部分保持明文、只留下三块高熵密文，这既是减少 I/O 的勒索优化，也是“间歇/局部加密”的典型取证特征。

## 原理

- **三个关键区段**：`smethod_1` 判断文件大小 `> 524288L` 后调用 `smethod_4(path, 131072, 0, fileInfo.Length / 2L, fileInfo.Length - 131072L)`。`int_0 = 131072` 是块长度，`int_1 = 0`、`long_0 = length/2`、`long_1 = length - 131072` 是三个读改写位置。
- **读改写流程**：`smethod_4` 对每个位置执行 `fileStream.Position = offset; Read(chunk, 0, 131072);`，调用 `smethod_5(key, iv, chunk)` 做 AES-256-CBC 加密，再 `fileStream.Position = offset; Write(cipher, 0, cipher.Length)`。`smethod_5` 设置 `Mode=1`（CBC）且 `Padding=1`（`PaddingMode.None`），因此 131072 字节（16 的整数倍）加密后长度不变，不会覆盖相邻区域。
- **为什么部分加密也能破坏文件**：常见文档/压缩包/数据库的头部、中央目录/索引、尾部元数据是解析所必需；破坏首、中、尾三段后，文件无法正常打开或解压。加密量约为 384KB / 文件大小，对 GB 级文件可显著减少 CPU 与磁盘 I/O，缩短勒索窗口。
- **RSA 封装与格式**：三段加密后，用与全量加密相同的每文件随机 key/IV，把 `ASCII(key + 分隔符 + IV)` 用硬编码 RSA-2048 公钥加密并追加到文件尾；解密方需要私钥解出 key/IV，再按三个位置局部解密。
- **边界条件**：代码用 `Length < 524288` 走全量、`Length > 524288` 走局部；恰好等于 524288 字节的文件既不进入全量分支也不进入局部分支，实际不会被加密（特定样本实现细节，可用于比对变种）。
- **取证特征**：文件在 offset 0、`length/2`、`length-128KB` 附近出现高熵块，其余区域仍是明文；文件长度基本不变（仅追加 RSA 块）；与全量加密（整文件高熵）明显不同，可用于识别间歇加密家族并定位被加密区段。`smethod_4`/`smethod_5` 的分块大小、位置数和位置计算（首/中/尾、固定步长、按百分比）是家族指纹。

## 触发条件

- 目标为 Windows 主机，样本有目标目录的读写与改名权限；文件扩展名命中白名单。
- 文件大小严格大于 `524288` 字节（本卡分支）；否则走小文件全量加密或恰好等于边界时不加密。
- 样本已生成该文件的随机 AES key/IV（`smethod_4` 内部调用 `smethod_9(32)`/`smethod_9(16)`），并持有硬编码 RSA 公钥。
- 攻击者服务器保留私钥；受害者无法仅凭公开的样本与密文恢复。

## 利用步骤

1. `smethod_1` 完成扩展名筛选、跳过勒索说明、清除只读属性后，读取 `fileInfo.Length`。
2. `Length > 524288` 时调用 `smethod_4(path, 131072, 0, length/2, length-131072)`。
3. `smethod_4` 生成随机 key/IV，依次在三个位置各读 128KB → `AES-256-CBC`（无填充）加密 → 写回同一位置。
4. 打开追加模式的 `FileStream`，把 `RSA_encrypt(ASCII(key + 分隔符 + IV))` 写到文件尾。
5. `File.Move` 改名为原名 + 随机 5 字符后缀；目录内写勒索说明。
6. 受害者需要攻击者用私钥解出 key/IV，再按三个区段分别解密；没有私钥时只能恢复未加密的大部分内容（但仍缺少关键区段）。

## PoC

原文为样本逆向，无武器化 PoC。以下为按截图还原的局部加密逻辑，仅用于分析与检测；AES 无填充要求块长度按 16 字节对齐（131072 满足）：

```python
import os
from Crypto.Cipher import AES

CHUNK = 131072
def partial_encrypt(path, key, iv):
    size = os.path.getsize(path)
    if size <= 524288:
        return  # 本样本走全量分支或不加密（==524288 时两分支都不命中）
    with open(path, "r+b") as f:
        for off in (0, size // 2, size - CHUNK):
            aes = AES.new(key, AES.MODE_CBC, iv)  # 每段新建 AES 对象，同一 key/IV 各自从 IV 开始
            f.seek(off)
            chunk = f.read(CHUNK)         # 131072, 16 的整数倍
            f.seek(off)
            f.write(aes.encrypt(chunk))
    # 之后追加 RSA_encrypt(ASCII(key + SEP + iv))；文件长度仅增加 RSA 块
```

```csharp
// 样本调用点（dnSpy 截图）
Class0.smethod_4(path, 131072, 0, fileInfo.Length / 2L, fileInfo.Length - 131072L);
// smethod_4 内：Position=offset -> Read(128KB) -> smethod_5(key,iv,chunk)
//               -> Position=offset -> Write(cipher)；最后 Append RSA 块
```

## 变体与关联

- **同样本密钥封装格式**：[[code-analysis-reverse-windows-cryptnet-hybrid-encryption-rsa-wrapped-aes-key-iv]] 描述每文件随机 key/IV、RSA 公钥封装与文件尾格式；本卡只替换“加密哪些区段”的策略。
- **家族/取证对照**：[[defense-detection-lockbit3-encrypted-file-artifacts]] 是 LockBit 3 的文件名/图标/勒索信现场特征；本卡补充“文件内容只被局部加密”的熵分布判据。
- **恢复对照**：[[defense-forensics-cryptoapi-aes256-file-encrypt-key-iv-recovery]] 从动态调试取 key/IV；[[defense-forensics-pyinstaller-ransomware-embedded-rsa-aes-ecb-recovery]] 利用样本内嵌私钥恢复。本卡样本无私钥，只能恢复未加密区段或等待密钥材料。
- **变体要点**：块大小（64KB/128KB/1MB）、位置数量（首尾、首中尾、固定步长、按文件百分比）、是否对每段使用同一 IV、是否加密文件尾 RSA 块；这些差异可作为家族聚类特征。

## 检测与防御

- 内容取证：对疑似加密文件按块计算熵，检查 offset 0、`length/2`、`length-128KB` 是否出现 128KB 高熵块而其余区域为明文/低熵；文件长度仅小幅增加（RSA 块），与全量加密不同。
- 文件侧：同目录 `RESTORE-FILES-*.txt`、随机 5 字符后缀、只读属性被清除；大量文件被原地修改而非整体重写。
- 进程/IO 侧：进程对大量文件执行“定位读取 128KB → 写回同一偏移”的 IO 模式；随后 `File.Move` 改名；.NET 样本带单实例互斥量。
- 防御：不可变/离线备份；WDAC/AppLocker 限制未知 .NET 程序；Controlled Folder Access；对关键目录的文件写入偏移分布做监控；定期验证备份可恢复性。
- 响应：优先保全未加密区段与内存中的 key/IV（`smethod_9` 结果可能短暂存在于进程内存）；不要支付赎金；用备份恢复并追踪 IOC。授权测试中不得对生产数据运行。
