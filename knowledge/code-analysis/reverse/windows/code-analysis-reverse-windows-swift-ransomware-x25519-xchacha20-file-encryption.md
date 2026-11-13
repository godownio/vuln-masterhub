---
id: code-analysis-reverse-windows-swift-ransomware-x25519-xchacha20-file-encryption
title: SWIFT 勒索软件文件加密方案：X25519 密钥 + CryptoPP XChaCha20，≤0x96000 全量、更大文件按 0x20000 分块加密
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: swift-ransomware-x25519-xchacha20-file-encryption
aliases:
- SWIFT 勒索
- swift_1@tutamail.com 勒索
- CryptoPP XChaCha20 勒索
- X25519 勒索密钥
- 0x96000 全量加密
- '[swift_1@tutamail.com].SWIFT'
tags:
- windows
- ransomware
- xchacha20
- x25519
- ecc
- cryptopp
- file-encryption
- malware-analysis
- swift
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V534
  verified_at: '2026-11-11T17:14:32+08:00'
  notes: 已对照原文全文与32张截图逐张核对：PE64/2024-02-15编译(img01)、HKCU\Software\Proton public 32B/full 80B(img04/05)、BCryptGenRandom+X25519钳位+XChaCha20_Policy(img23及zoom)、≤0x96000整文件+0x78(120)字节尾(img21)、大文件0x20000分块(img22，正文0x2000为笔误已按截图更正)、MoveFileW改名(img24/25)。原文称AES+ECC但截图实为XChaCha20+X25519，卡内已注明差异。未执行样本
---

## 一句话结论

SWIFT 勒索样本（PE64，2024-02-15 编译）在 `HKCU\Software\Proton` 下保存 32 字节 `public` 与 80 字节 `full` 密钥材料，反编译代码显示其对 32 字节随机值做 X25519 私钥钳位（`pBuffer[0] &= 0xF8`、`pBuffer[31] = (pBuffer[31] & 0x3F) | 0x40`），并用 Crypto++ 的 `XChaCha20_Policy` 做文件加密；文件 ≤0x96000 字节时整文件读入加密后再追加固定尾部，更大文件按 0x20000（128KB）分块流式加密，最后用 `MoveFileW` 改名为 `<原名>[swift_1@tutamail.com].SWIFT`。赎金信与文章正文声称 “AES and ECC”，但截图中的实际算法是 XChaCha20 + X25519（ECC），并非 AES。

## 原理

- **密钥材料落注册表**：样本在 `HKEY_CURRENT_USER\Software\Proton` 写入 `public`（REG_BINARY，32 字节）与 `full`（REG_BINARY，80 字节）两个值。32 字节对应 Curve25519 公钥/私钥长度；80 字节可能是完整密钥结构（含私钥、公钥与元数据）。
- **X25519 私钥钳位**：反编译代码先 `BCryptGenRandom(0x164, pBuffer, 0x20u, 2u)` 取 32 字节随机数，然后执行 `pBuffer[0] &= 0xF8; pBuffer[31] = pBuffer[31] & 0x3F | 0x40;`——这正是 RFC 7748 的 X25519 私钥 clamp（清低 3 位、清最高位、置次高位），说明样本使用 X25519 而非 RSA 做非对称密钥封装。
- **对称加密是 XChaCha20**：代码中构造 `CryptoPP::SymmetricCipherFinal<CryptoPP::ConcretePolicyHolder<CryptoPP::XChaCha20_Policy, CryptoPP::AdditiveCipherTemplate<...>>>`，并配合 SHA-256 常量与 32 字节密钥派生调用。XChaCha20 是流密码，加密长度不变、不需要填充，适合按任意块大小流式处理。
- **文件处理分支**：`CreateFileW` 以 `GENERIC_READ|GENERIC_WRITE` 打开文件，`GetFileSizeEx` 后判断 `Filesize.QuadPart <= 0x96000`（614400 字节）：小文件整文件读入内存，加密后写回，并额外写入 0x78（120）字节尾部数据；大文件则 `ReadFile` 按 0x20000（131072 字节）循环读取、加密、写回，分配和长度计算中包含额外固定开销（截图可见 `+56164` 一类常数）。
- **与正文的差异**：文章正文写“按 0x2000 大小分块”，但反编译截图中循环与缓冲区大小均为 `0x20000`（128KB）；卡片以截图代码为准，0x2000 很可能是笔误。
- **改名与勒索信**：加密完成后 `MoveFileW` 把文件改名为 `<原名>[swift_1@tutamail.com].SWIFT`；目录中写入 2KB 的 `#SWIFT-Help.txt`，并用 `ShellExecuteW("open")` 打开。赎金信自称 “We use AES and ECC algorithms”，属于对受害者的笼统/误导性描述，反向分析应以代码中的 XChaCha20 + X25519 为准。
- **为什么这样设计**：X25519 用于把每个文件的对称密钥安全封装给攻击者（只有攻击者持有对应私钥可解），XChaCha20 用于高速流式加密大文件；分块处理避免一次性读入 GB 级文件，兼顾速度与内存占用。该组合与常见的 RSA-2048 + AES-CBC 勒索家族不同，可作为家族指纹。

## 触发条件

- 受害主机为 64 位 Windows，样本以当前用户/管理员权限运行，对目标目录有读写与改名权限。
- 样本可访问并遍历本地磁盘/网络共享（`GetLogicalDriveStringsW`、`GetDriveTypeW`、`FindFirstFileW`）。
- 文件未被进程占用（样本会先终止数据库/备份/杀软相关进程与服务）。
- 注册表 `HKCU\Software\Proton` 可写，用于保存密钥材料。

## 利用步骤

1. 样本启动后生成/读取 `HKCU\Software\Proton` 下的 `public`、`full` 密钥材料。
2. 对每个目标文件打开读写句柄并取大小：≤0x96000 字节走整文件读入 → XChaCha20 加密 → 写回 + 0x78 字节尾部；更大文件按 0x20000 字节分块流式加密。
3. 用 X25519 将文件对称密钥封装进文件尾部/密钥结构，使受害者无法自行解密。
4. `MoveFileW` 改名为 `<原名>[swift_1@tutamail.com].SWIFT`，目录写入 `#SWIFT-Help.txt`。
5. 通过 `ShellExecuteW("open")` 打开勒索信，并配合壁纸/注册表项持续展示勒索信息。

## PoC

原文为样本逆向，无武器化 PoC。按截图还原的加密流程伪代码（密钥封装与尾部格式未完全还原，仅作分析参考）：

```text
key = BCryptGenRandom(32)
key[0] &= 0xF8; key[31] = (key[31] & 0x3F) | 0x40     // X25519 clamp
save_to_registry(HKCU\Software\Proton, public/full, key)

open(target, GENERIC_READ|GENERIC_WRITE)
size = GetFileSizeEx()
if size <= 0x96000:
    buf = read_whole_file()
    out = XChaCha20_encrypt(buf, key) + trailer(0x78)
    write_file(out)
else:
    for chunk in read_chunks(0x20000):
        write_file(XChaCha20_encrypt(chunk, key))
move_file(target, target + "[swift_1@tutamail.com].SWIFT")
```

## 变体与关联

- 变体：同类“每文件随机对称密钥 + 非对称封装”的勒索设计；CryptNet 用 RSA-2048 封装 AES-256-CBC key/IV 并追加文件尾，见 `code-analysis-reverse-windows-cryptnet-hybrid-encryption-rsa-wrapped-aes-key-iv`。
- 关联：大文件间歇/分块加密的取证特征见 `code-analysis-reverse-windows-ransomware-large-file-intermittent-encryption-three-128kb`；本样本是流式全文件分块（0x20000），不是首/中/尾三段。
- 关联：ChaCha20 在二进制中的识别特征见 `code-analysis-reverse-chacha20-binary-identification-features`；锁文件扩展名与家庭指纹可用于威胁情报比对。

## 检测与防御

- 检测：文件名后缀 `[swift_1@tutamail.com].SWIFT`、目录中 2KB `#SWIFT-Help.txt`、`HKCU\Software\Proton` 的 `public`/`full` 二进制值；进程加载 Crypto++、出现 `XChaCha20_Policy`/X25519 clamp 常量；大量文件短时间被改名/高熵化。
- 防御：离线/不可变备份；限制普通用户对启动目录与注册表 Run/Proton 键的写权限；EDR 监控文件批量改名、`MoveFileW` 高频调用与勒索信文件名；关闭不必要的磁盘共享。
- 取证：按文件大小区分全量/分块加密路径；小文件尾部 0x78 字节与大文件分块边界是格式指纹；注册表 32/80 字节密钥材料可用于家族归因（私钥在攻击者侧，无法直接解密）。
