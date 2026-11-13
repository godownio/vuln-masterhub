---
id: ctf-forensics-png-lsb-embedded-fat12-disk-testdisk
title: PNG LSB 内嵌 FAT12 软盘镜像：zsteg b8 平面提取磁盘 + testdisk/FTK 恢复 _LAG.ICO 取 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: png-lsb-embedded-fat12-disk-testdisk
tags:
- ctf
- forensics
- stego
- png
- lsb
- zsteg
- fat12
- testdisk
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V570
  verified_at: '2026-11-12T09:27:10+08:00'
  notes: 已对照 12973 原文与图 26-30 核对：zsteg -a 命中 b8,rgb,lsb,xy 为 DOS/MBR boot sector、FAT (12 bit)、2880 扇区 1.44MB；按该参数 zsteg -e 提取 disk，FTK/X-Ways 与 testdisk 均列出 25.1KB 的 _LAG.ICO，打开得 CTF{FAT12_FTW...}；命令与 FAT12 断言有截图实证，未复跑。
url: /docs/ctf/forensics/ctf-forensics-png-lsb-embedded-fat12-disk-testdisk/
draft: false
kb_aliases:
- zsteg 提取磁盘镜像
- PNG 藏 FAT12
- LSB 内嵌 DOS/MBR 引导扇区
- testdisk 恢复软盘镜像文件
- BSidesSF diskimage 类型题
---

## 一句话结论

对可疑 PNG 执行 `zsteg -a`，若某个位平面组合（如 `b8,rgb,lsb,xy`）被识别为 `DOS/MBR boot sector` 或 FAT 文件系统，就用 `zsteg -e 'b8,rgb,lsb,xy' x.png > disk` 把整块磁盘镜像按位重组提取出来；再用 testdisk 打开镜像列出文件（按 `c` 复制）或用 FTK Imager 挂载并导出，即可恢复出藏有 flag 的文件（如 `_LAG.ICO`）。

## 原理

- **PNG 位平面**：PNG 解码后每个像素有 R/G/B（/A）通道字节；把磁盘镜像的每个字节拆成 8 个位，逐位写入像素通道的最低位/指定平面，视觉上几乎无变化。`zsteg` 会枚举位平面 b1~b8、通道顺序（rgb/bgr）与扫描顺序（xy/yx）组合，把位流按字节重组并用文件签名规则识别内容。
- **为什么能藏下整块磁盘**：LSB 每通道每像素 1 bit，一张百万像素级 PNG 可藏数百 KB 数据——足够容纳 1.44MB 软盘镜像的一部分；题目常用压缩/稀疏磁盘或较小镜像。`zsteg -a` 的多组合扫描直接按签名（`DOS/MBR boot sector`）指出正确的平面参数。
- **FAT12 软盘结构**：提取出的镜像带标准 DOS 引导扇区与 FAT12 文件系统（1.44MB 软盘布局），testdisk 能解析分区/引导扇区并列出根目录文件；FTK Imager 可直接作为磁盘镜像加载后浏览/导出。
- **为什么恢复文件能得 flag**：题目把 flag 放在文件内容或文件名/图标数据中；`_LAG.ICO` 这种命名也暗示按文件内容查看即可。testdisk 的 `c`（copy）会把选中文件导出到当前目录。

## 触发条件

- 拿到一张可疑图片（题面常提示隐写/磁盘），常规图片查看无异常。
- `zsteg -a` 输出中出现 `DOS/MBR boot sector`、`FAT`、`PGP Secret Key` 等二进制签名。
- 本机有 zsteg（Ruby gem）、testdisk 或 FTK Imager（Windows）。

## 利用步骤

1. `zsteg -a attachment.png` 扫描全部位平面组合，定位被识别为磁盘/文件系统的通道参数。
2. 按该参数提取：`zsteg -e 'b8,rgb,lsb,xy' attachment.png > disk`。
3. `file disk` 确认是 DOS/MBR 引导扇区/FAT 镜像。
4. 方案一：FTK Imager 添加该镜像为证据，浏览文件系统，导出目标文件（如 25KB 的 `_LAG.ICO`），改后缀/直接打开查看。
5. 方案二：`testdisk disk` → Proceed → 分区表类型（None/Intel）→ Analyse → 列目录，选中目标文件按 `c` 复制出来，再打开取 flag。

最小化 PoC：

```
zsteg -a attachment.png | grep -i "DOS/MBR\|FAT"
zsteg -e 'b8,rgb,lsb,xy' attachment.png > disk
file disk
testdisk disk        # List 后选中 _LAG.ICO 按 c 复制
```

## 变体与关联

- 同一 zsteg 手法也可提取 URL/OpenPGP 密钥等文本载荷（按 `text`/`file` 规则识别）。
- 提取出的 FAT 镜像还可能含删除文件，需要 FAT 表/簇链恢复或 `photorec` 按签名 carve。
- binwalk/foremost 可按文件签名从二进制中分离嵌入文件，适合镜像内已损坏的目录结构。

## 检测与防御

- 隐写检测：`zsteg -a`、StegSolve 位平面查看、统计 LSB 直方图/卡方分析；异常大的 PNG 与正常图片对比体积。
- 与普通图片隐写不同，内嵌完整磁盘镜像会在 LSB 中出现大量结构化二进制（引导扇区魔数 `55 AA`、FAT 表），签名扫描很容易命中。
- CTF 之外：LSB 隐写是常见数据夹带方式，DLP 可对图片做位平面扫描与文件 carve。
