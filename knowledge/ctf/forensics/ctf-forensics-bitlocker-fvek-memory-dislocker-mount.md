---
id: ctf-forensics-bitlocker-fvek-memory-dislocker-mount
title: BitLocker 内存取证：Volatility 提取 FVEK + dislocker 离线挂载解密卷
type: scenario
domain: ctf
path: ctf/forensics
technique: bitlocker-fvek-memory-dislocker-mount
aliases:
- BitLocker 内存取证
- Volatility bitlocker FVEK
- dislocker 解密 BitLocker
- FVEK 提取挂载
- memdump 解 BitLocker
tags:
- forensics
- memory
- bitlocker
- volatility
- dislocker
- fvek
- disk-image
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:13:10+08:00'
  notes: 已对照原文与图 57-59 核对：vol2 bitlocker 提取 FVEK、fdisk Start=128→offset 65536、dislocker -k、ntfs-3g 挂载及失败换候选一致；未复跑镜像。
---

## 一句话结论

BitLocker 卷处于解锁/挂载状态时，直接用于数据加解密的 FVEK 必须常驻内存；对内存镜像用 Volatility 的 bitlocker 插件批量提取 FVEK 候选文件，排除全零项后结合 `fdisk` 得到的分区字节偏移，用 `dislocker --offset ... -k <fvek> -- <image> <mnt>` 解密，再以 `ntfs-3g` 只读挂载 `dislocker-file`，即可读取加密卷中的文件与 flag。

## 原理

- **BitLocker 密钥层级**：FVEK（Full Volume Encryption Key）直接加密磁盘数据；FVEK 由 VMK（Volume Master Key）加密后存放在卷元数据中；VMK 又由一个或多个保护器（密码、TPM、恢复密钥、启动 PIN）保护。解锁时保护器解出 VMK，VMK 解出 FVEK，FVEK 被加载进 RAM 供磁盘驱动实时加解密。
- **为什么内存里能拿到 FVEK**：只要卷处于解锁状态，系统就必须在内存中保留可用的 FVEK 或其派生密钥；内存镜像会捕获这些结构。Volatility 的 bitlocker 插件扫描内存中的 FVEK 结构（如 `FVEc`/`Cngb` 标签），把候选按地址导出为 dislocker 可识别的 `.fvek` 文件。
- **为什么要尝试多个候选**：插件会把所有可能的 FVEK 结构都列出来，其中包含全零/无效项；同一把密钥可能在多个地址重复出现。用 dislocker 解密失败（如 “NTFS signature is missing”）就换下一个候选。
- **为什么要算偏移**：题目给的往往是整盘镜像，BitLocker 加密的是其中某个分区。`fdisk -l` 显示分区起始扇区（如 128），乘以扇区大小 512 得到字节偏移 65536；dislocker 的 `--offset` 必须指向该分区起点，否则解密后的数据不是有效的 NTFS。
- **dislocker 的工作方式**：它读取卷元数据和 FVEK，在输出目录生成 `dislocker-file`（一个已解密的虚拟 NTFS 卷）；再用 `mount -o loop,ro -t ntfs-3g` 把它挂到第二个目录，即可像普通文件系统一样读取。

## 触发条件

- 拿到 Windows 内存镜像（如 `memdump.mem`），且目标 BitLocker 卷在采集时处于解锁/使用状态。
- 同时拿到对应的整盘或分区镜像（如 `0xGame.dd`），且知道/能推算出分区偏移。
- 能运行 Volatility 2 或 3 及对应 bitlocker 插件；Linux 侧能使用 `dislocker`、`ntfs-3g`、`mount`。
- 内存镜像 profile 可识别（Windows 常见版本），或能提供自制 profile。

## 利用步骤

1. 识别内存镜像：`python vol.py -f memdump.mem imageinfo`，记录 Suggested Profile（如 `Win10x64`）。
2. 提取 FVEK 候选：
   - Volatility 2：`python vol.py -f memdump.mem --profile=Win10x64 bitlocker --dislocker ./dislockerkeys`
   - Volatility 3：`python vol.py -f memdump.mem -vvv windows.bitlocker.BitlockerFVEKScan --tags FVEc Cngb None --dislocker`
   输出会给出 FVEK 地址、算法（AES-128/256）和导出的 `.fvek` 文件路径；全零的十六进制值是无效候选。
3. 分析磁盘镜像分区：`fdisk -l 0xGame.dd`，找到 BitLocker 分区起始扇区 `Start`，计算 `offset = Start * 512`。
4. 解密卷：`sudo dislocker -v --offset <offset> -k <候选.fvek> -- 0xGame.dd /mnt/dislocker_tmp`；成功后输出目录出现 `dislocker-file`。
5. 只读挂载：`sudo mount -o loop,ro -t ntfs-3g /mnt/dislocker_tmp/dislocker-file /mnt/decrypted`。
6. 读取目标文件（如 `flag.txt`）；失败则换下一个 FVEK 候选重复 4–5 步。
7. 清理：`umount` 两个挂载点，删除临时目录。

## PoC

```bash
# 1. 识别内存镜像
python vol.py -f memdump.mem imageinfo

# 2. 提取 FVEK 候选（vol2 示例）
mkdir -p ./dislockerkeys
python vol.py -f memdump.mem --profile=Win10x64 bitlocker --dislocker ./dislockerkeys

# 3. 计算分区偏移（示例 Start=128, 512 字节/扇区 -> 65536）
fdisk -l 0xGame.dd

# 4. 用候选 FVEK 解密，失败则换下一个
sudo mkdir -p /mnt/dislocker_tmp /mnt/decrypted
sudo dislocker -v --offset 65536 \
  -k ./dislockerkeys/0xe000899f7680-Dislocker.fvek -- \
  0xGame.dd /mnt/dislocker_tmp

# 5. 挂载解密后的 NTFS 卷
sudo mount -o loop,ro -t ntfs-3g \
  /mnt/dislocker_tmp/dislocker-file /mnt/decrypted
cat /mnt/decrypted/flag.txt
```

说明：PoC 为原文流程的结构化复现，未在本机执行；原文先用 vol2 提取多个 FVEK，首个候选挂载时报 “NTFS signature is missing”，换用 AES-128 候选后成功读出 flag；vol3 的 `BitlockerFVEKScan` 流程等价。

## 变体与关联

- 变体（工具）：Passware Kit Forensic 可直接从内存镜像恢复 VMK/恢复密钥并解密，属于“一把梭”；Elcomsoft 等取证套件同理。
- 变体（密钥层级）：直接取 FVEK 绕过 VMK/保护器；也可从内存中提取 VMK 或恢复密钥，再走正常解锁流程。
- 变体（其他加密卷）：TrueCrypt/VeraCrypt 的卷主密钥常驻内存，用 `aeskeyfind`/Volatility 插件提取后挂载；LUKS 可从内存/内核密钥环恢复。
- 关联：[[ctf-forensics-truecrypt-memory-key-mount]]（TrueCrypt/VeraCrypt 内存密钥）；[[ctf-forensics-veracrypt-aes-xts-manual-sector-decrypt]]；[[ctf-forensics-partial-ewf-ntfs-openssl-memory-decrypt]]（内存中取密钥解 NTFS）；[[defense-forensics-veracrypt-key-from-mobile-notes-cross-evidence]]。
- 边界：卷在采集时已锁定/休眠且密钥被清除、内存镜像不完整、FVEK 被硬件保护（如 TPM-only 且未解锁）时，插件可能提不出有效候选；整盘偏移算错会得到无效 NTFS。

## 检测与防御

- 检测：内存镜像中出现 BitLocker FVEK/VMK 结构；主机上出现 `dislocker`、`ntfs-3g` 挂载 BitLocker 卷的行为；敏感磁盘镜像被复制到分析环境。
- 防御：启用 TPM+PIN 或启动密钥，避免仅靠自动解锁；休眠/睡眠前锁定卷；限制内存转储权限（禁用不必要的崩溃转储、保护页文件）；对取证镜像做访问控制与加密；定期轮换恢复密钥。
