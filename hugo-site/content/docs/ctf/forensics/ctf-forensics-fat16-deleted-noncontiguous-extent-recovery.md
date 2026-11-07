---
id: ctf-forensics-fat16-deleted-noncontiguous-extent-recovery
title: FAT16 删除文件非连续簇恢复：按接口连续性拼接 4 段并 CRC32 校验，提取 Lua 状态机常量
type: scenario
domain: ctf
path: ctf/forensics
technique: fat16-deleted-noncontiguous-extent-recovery
tags:
- ctf
- forensics
- fat16
- file-carving
- deleted-file
- noncontiguous
- crc32
- lua
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:35+08:00'
  notes: 对照无人机236：BPB/dataoff=49664、簇 120/911/2048/4091、CRC32 c015417b、LIMITS 常量一致
url: /docs/ctf/forensics/ctf-forensics-fat16-deleted-noncontiguous-extent-recovery/
draft: false
kb_aliases:
- 失落的 Lua
- FAT16 删除恢复
- MISSION.LUA 恢复
- 非连续簇拼接
- 4 extents unresolved
- CRC32 校验拼接
- 0xE5 目录项
---

## 一句话结论

FAT16 镜像中删除的 MISSION.LUA 名字仍在但 FAT 链被清空、文件被非连续分配；按 BOOT.LOG 提示的全文件 CRC32 与“接口连续性”判据，在多个带缓存头的诱饵片段中挑出簇 120、911、2048、4091 四段拼成 2007 字节，CRC32 与提示一致后从 Lua 状态机常量推导 flag。

## 原理

- FAT16 的根目录项 32 字节，首字节 `0xE5` 表示删除；删除只清目录项与 FAT 链，数据簇通常仍在。本题 `sdcard.img` 4MB，BPB：`bps=512`、`spc=1`、`reserved=1`、`NFAT=2`、`rootent=512`、`fatsz=32`，数据区起点 `dataoff=49664`。
- 根目录第 4 项首字节 `0xE5`，恢复出 `MISSION.LUA` 起始簇 120、大小 2007 字节。由于 FAT 链被清空，不能按链顺序读取；文件被拆成 4 个 extent，分散在非连续簇。
- `BOOT.LOG` 给出关键提示：`lua restore: directory entry found; 4 extents unresolved; whole-file crc32=c015417b`。CRC32 成为拼接结果的硬校验，4 extents 说明需要找 4 段。
- 全盘扫描非零簇得到候选：120、300、650、911、1200、1700、2048、2500、3100、3600、4091。其中 300~3600 的七个片段都带 “cached” 头尾，是参数值为干扰项的诱饵缓存副本（`altitude_min=900`、`yaw_high=35000` 等）；真实脚本四段接口严丝合缝：
  - 簇 120 是文件头加 LIMITS 表，结尾停在 `local function altitude_ok(alt`；
  - 簇 911 从 `itude_cm)` 续起，结尾停在 `function update(mode, altitude_cm, yaw`；
  - 簇 2048 从 `_cd, rc7, now_ms)` 续起接状态机主体；
  - 簇 4091 从 `_min then` 续起接尾部，共 471 字节收尾。
- 按 120、911、2048、4091 拼接取前 2007 字节，CRC32=`c015417b` 与 BOOT.LOG 一致——接口连续性判据与 CRC 校验双源验证拼接正确性。
- flag 推导取恢复脚本的 LIMITS 状态机常量：`initial_mode=5`、`hold_ms=7000`、`altitude_min_cm=1320`、`altitude_max_cm=1335`、`yaw_high_cd=35800`、`yaw_low_cd=200`、`rc7_min=1800`、`final_mode=6`、`deadline_ms=12000`；材料串 `5|7000|1320|1335|35800|200|1800|6|12000` 的 SHA-256 前 32 位 hex 即 flag。

## 触发条件

- 拿到 FAT16/FAT32 镜像与删除文件线索（BOOT.LOG、目录项、大小、CRC）。
- FAT 链已被清空或损坏，文件非连续分配；镜像中还有诱饵/缓存副本。
- 有可用的拼接正确性判据（CRC32、文件头/尾、语法/接口连续性）。
- 目标文件内容可进一步解析（如 Lua 状态机常量）。

## 利用步骤

1. 解析 BPB，计算 `dataoff = reserved + NFAT*fatsz + rootent*32/bps`；遍历根目录找首字节 `0xE5` 的删除项。
2. 恢复文件名、起始簇、文件大小；检查 FAT 链是否为空/损坏。
3. 全盘扫描非零簇，按数据类型/文本特征筛选候选片段；识别带缓存头/重复参数的诱饵。
4. 按“接口连续性”拼接：检查每段结尾与下一段开头是否能拼成完整 token/语法；用 CRC32、文件头/尾、可解析性验证。
5. 对恢复文件做语法/语义分析，提取常量、密钥或状态机；按题目规则生成 flag。

## PoC

```python
import zlib, hashlib

d = open("sdcard.img", "rb").read()
dataoff = 49664
cl = lambda c: d[dataoff + (c - 2) * 512 : dataoff + (c - 2) * 512 + 512]

f = b"".join(cl(c) for c in [120, 911, 2048, 4091])[:2007]
print(format(zlib.crc32(f) & 0xffffffff, "08x"))   # c015417b
print(f[:80])                                      # 检查文件头/语法连续性

m = "5|7000|1320|1335|35800|200|1800|6|12000"
print("flag{" + hashlib.sha256(m.encode()).hexdigest()[:32] + "}")
```

```python
# 目录项解析（简化）
for i in range(rootent):
    e = root[i*32:(i+1)*32]
    if e[0] == 0xE5:
        name = e[0:11].decode("ascii", "ignore")
        start = int.from_bytes(e[26:28], "little")
        size = int.from_bytes(e[28:32], "little")
        print(name, start, size)   # MISSION.LUA 120 2007
```

## 变体与关联

- 变体：FAT32/exFAT、NTFS 的删除恢复；非连续 extent 可用文件签名、语法、CRC、熵分布拼接。
- 变体：诱饵片段可通过“缓存头/重复参数/时间戳”识别；若没有 CRC，可用文件格式解析器（Lua/Python/PE）验证完整性。
- 关联：[[ctf-forensics-midi-shared-tick-register-stego]]（结构化数据隐写）、[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]（固件/文件系统分析）。
- 边界：簇大小、保留扇区、FAT 数因镜像而异；删除后簇可能被覆盖；非连续拼接依赖足够强的正确性判据。

## 检测与防御

- 检测：镜像中存在 `0xE5` 目录项与孤立数据簇；多个片段带相似缓存头/参数（诱饵）；恢复文件语法在接口处断裂或 CRC 不符。
- 防御/取证：删除敏感文件时使用安全擦除/全盘加密；保留 BOOT.LOG 等元数据；对镜像做只读挂载与哈希校验；恢复时记录每一步判据。
- 加固（若用于隐蔽存储）：不要只清 FAT 链；对文件做加密与完整性保护；避免在镜像中留下缓存副本。
