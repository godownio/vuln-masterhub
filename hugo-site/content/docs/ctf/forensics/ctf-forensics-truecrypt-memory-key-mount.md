---
id: ctf-forensics-truecrypt-memory-key-mount
title: TrueCrypt 内存镜像主密钥提取：进程/命令行定位 + 密钥搜索 + 挂载加密卷
type: scenario
domain: ctf
path: ctf/forensics
technique: truecrypt-memory-master-key-extraction
tags:
- ctf
- forensics
- truecrypt
- memory-forensics
- full-disk-encryption
- key-extraction
- mount
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T14:05:49+08:00'
  notes: 已对照 91111 原文数据应急第二题与图 09-12 核对：TrueCrypt.exe PID 2128、Elcomsoft 主密钥搜索、1.evk 挂载及 strings flag{ 非预期解均一致。PoC 未在本机复跑。
url: /docs/ctf/forensics/ctf-forensics-truecrypt-memory-key-mount/
draft: false
kb_aliases:
- TrueCrypt 内存取证
- 全盘加密密钥提取
- Elcomsoft Forensic Disk Decryptor
- Volume Master Key
- .evk 挂载
- DumpIt 内存镜像
---

## 一句话结论

TrueCrypt/VeraCrypt 卷挂载期间，卷主密钥（Volume Master Key）必须常驻内存；拿到内存镜像后，先在进程/命令行中确认 `TrueCrypt.exe` 正在运行，再用 Elcomsoft Forensic Disk Decryptor、`aeskeyfind` 或 Volatility 插件搜索卷主密钥，保存为 `.evk`/keyfile 后挂载对应加密卷，即可读取其中的文件与 flag。若镜像未压缩/未清理，直接在内存中 `strings` 搜索 `flag{` 也可能命中非预期解。

## 原理

- **FDE 密钥驻留**：TrueCrypt 使用头部密钥加密卷主密钥；挂载时输入口令派生头部密钥、解出主密钥后，主密钥留在内核/驱动内存中用于实时加解密。只要卷处于挂载状态，内存里就有主密钥结构。
- **内存镜像**：`DumpIt.exe`、`winpmem`、VM 快照等可捕获物理内存；题目中的 `vol2_cmdline.csv` 显示 `TrueCrypt.exe` PID 2128，说明镜像采集时卷已挂载。
- **密钥搜索**：专用工具（Elcomsoft Forensic Disk Decryptor）会扫描内存中的 TrueCrypt key schedule/主密钥结构，输出候选 key blob；也可用 `aeskeyfind`、Volatility 的 TrueCrypt/VeraCrypt 插件，或按已知结构特征搜索。
- **挂载**：把候选 key 保存为 `.evk` 或工具要求的 keyfile，选择对应加密卷/分区，工具用主密钥直接解密数据区（不需要原口令）；挂载后像普通磁盘一样浏览。
- **非预期解**：若内存镜像未压缩且 flag 以明文/文件缓存形式存在，`strings -a memory.raw | grep 'flag{'` 可能直接得到 flag；这是取证中应先做的快速检查。
- **为什么可复用**：内存取证是 FDE 的主要突破口之一；锁屏、休眠、挂载状态都可能保留密钥。企业取证/应急时应优先采集内存，再关机。

## 触发条件

- 有目标主机的物理内存镜像（raw/aff4/VM snapshot），且采集时加密卷处于挂载/使用状态。
- 镜像中存在 TrueCrypt/VeraCrypt 进程、驱动或密钥结构；进程列表/命令行可佐证。
- 有密钥搜索工具（Elcomsoft、aeskeyfind、Volatility 插件）与对应卷/分区镜像。
- 若走非预期解，flag/敏感文件以明文或可搜索形式残留在内存。

## 利用步骤

1. 解压取证包，确认内存镜像与磁盘/分区镜像；用 Volatility 的 `windows.pslist`/`windows.cmdline` 或题目给出的 `cmdline.csv` 查找 `TrueCrypt.exe`、`DumpIt.exe` 等进程。
2. 先做快速检查：`strings -a memory.raw | grep -a 'flag{'`、`grep -a 'BEGIN'`、常见口令/密钥关键字；记录命中偏移与上下文。
3. 用 Elcomsoft Forensic Disk Decryptor 加载内存镜像，执行 key search；或运行 `aeskeyfind memory.raw` / Volatility TrueCrypt 插件，收集候选 Volume Master Key。
4. 将候选 key 保存为 `.evk`/keyfile；在工具中选择对应的 TrueCrypt 卷/分区镜像，执行 mount。
5. 挂载成功后浏览卷内文件，查找 flag/合同/密码本等目标；记录文件路径、哈希与时间。
6. 若 key 搜索无结果，检查镜像是否完整、卷是否已卸载、是否 VeraCrypt 新格式、是否使用隐藏卷；尝试多种工具与 key 结构偏移。
7. 对非预期明文命中，仍需用文件系统/进程上下文验证其真实性，避免把缓存片段误判为完整 flag。

## PoC

```bash
# 1) 快速检查内存中的明文
strings -a memory.raw | grep -a -n 'flag{'

# 2) 查看进程/命令行（Volatility 3）
vol -f memory.raw windows.pslist
vol -f memory.raw windows.cmdline

# 3) 搜索 AES 密钥候选（aeskeyfind）
aeskeyfind memory.raw

# 4) Elcomsoft Forensic Disk Decryptor（GUI）
#    - 打开内存镜像 -> Key Search -> 选择 TrueCrypt Volume Master Keys
#    - 保存候选 key 为 1.evk
#    - 选择加密卷/分区 -> Mount -> 指定盘符 -> 浏览文件
```

原文在内存镜像中命中 `TrueCrypt Volume Master Keys`，保存为 `1.evk` 后成功挂载并读取 flag；另在字符串搜索中直接命中 `flag{...}`（非预期解）。

## 变体与关联

- **加密软件变体**：VeraCrypt（新格式/隐藏卷）、BitLocker（ recovery key/TPM）、LUKS（dm-crypt key）、FileVault；密钥结构与搜索工具不同，思路相同。
- **采集变体**：DumpIt/winpmem/VM 快照/休眠文件/hiberfil.sys/crash dump；休眠文件常包含完整内存与密钥。
- **密钥搜索变体**：aeskeyfind、Volatility 插件、bulk_extractor、按 key schedule 特征扫描；也可从进程内存 dump 中提取。
- **关联卡片**：[[ctf-forensics-veracrypt-aes-xts-manual-sector-decrypt]]（VeraCrypt 数据区手动解密）、[[defense-forensics-veracrypt-key-from-mobile-notes-cross-evidence]]（VeraCrypt key 取证）、[[ctf-forensics-partial-ewf-ntfs-openssl-memory-decrypt]]（内存/磁盘镜像取证）。
- **边界**：卷已卸载/重启后密钥可能被清除；内存镜像不完整、被压缩/加密、或使用隐藏卷时搜索可能失败；商业工具输出需人工验证 key 与卷匹配。

## 检测与防御

- **防御（FDE 使用方）**：依赖 FDE 时同时启用 TPM + PIN/预启动认证；离开时休眠/关机而非仅锁屏；限制物理访问、DMA 端口与调试接口；对高敏系统使用内存加密/机密计算。
- **检测（取证/蓝队）**：检查内存镜像中的 TrueCrypt/VeraCrypt 进程与驱动；审计 `DumpIt`/`winpmem` 等内存采集工具的使用；监控加密卷挂载/卸载与异常 keyfile 访问。
- **应急**：事件响应先采集内存再关机；保留镜像哈希与链式 custody；对提取的 key/明文做访问控制与销毁计划。
- **合规**：内存镜像可能含大量个人数据，分析需最小化、授权与留存期限；报告只引用必要证据。
