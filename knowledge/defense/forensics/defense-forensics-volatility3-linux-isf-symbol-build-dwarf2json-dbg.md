---
id: defense-forensics-volatility3-linux-isf-symbol-build-dwarf2json-dbg
title: Volatility3 Linux 符号表制作：发行版 dbg 包解出 System.map+vmlinux，dwarf2json 生成 ISF JSON 放入 symbols/linux
type: scenario
domain: defense
path: defense/forensics
technique: volatility3-linux-isf-symbol-build-dwarf2json-dbg-package
aliases:
- Volatility3 Linux 符号表
- dwarf2json 生成 ISF
- linux-image-dbg 包
- vmlinux System.map dwarfdump 替代
- vol3 linux.pslist 无法解析
- Debian/Ubuntu 内核符号
- Volatility3 symbols/linux
tags:
- linux
- forensics
- memory
- volatility3
- isf
- dwarf2json
- symbols
- kernel
- debian
- ubuntu
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V553
  verified_at: '2026-11-11T23:05:12+08:00'
  notes: 已对照原文与 19 张截图核对：图 14 vol3 banner 得 Debian 5.10.0-21-amd64；图 16 下载 linux-image-5.10.0-21-amd64-dbg_5.10.162-1_amd64.deb(762M)；图 17 tar 解出 System.map/vmlinux；dwarf2json 命令与图 18/19 的 linux.pslist/linux.bash 成功输出一致；与库内 Vol2 profile 卡为不同工具链。未验证点：原文未展示 dwarf2json 输出日志，--symbol-dirs 为通用说明。
---

## 一句话结论

Volatility3 分析 Linux 内存镜像时如果没有匹配的 ISF 符号表，先用 `banner` 读出内核版本与发行版，去对应发行版仓库下载 `linux-image-<ver>-dbg` 调试包，解出 `/usr/lib/debug/boot/System.map-<ver>` 与 `vmlinux-<ver>`，用 `dwarf2json linux --system-map ... --elf ... > <ver>.json` 生成 ISF JSON 放进 `volatility3/framework/symbols/linux/`，之后 `linux.pslist`、`linux.bash` 等插件即可正常解析。

## 原理

- **Vol3 与 Vol2 的差异**：Vol2 用 profile（module.dwarf + System.map 打包 zip），Vol3 用 ISF（JSON 符号表）描述内核结构体布局与符号地址；没有匹配 ISF 时，插件会报找不到符号/无法建立地址空间，或解析出错误结构。
- **为什么需要两样东西**：`System.map` 提供符号名到地址的映射（进程链表、网络结构等全局对象），`vmlinux`（带 DWARF 调试信息的 ELF）提供结构体字段名/偏移/大小，二者缺一不可；`dwarf2json linux` 把两者合并成 ISF JSON。
- **版本必须精确**：内核版本串（如 `5.10.0-21-amd64`、`5.4.0-100-generic`）包含发行版补丁级别与编译配置，结构体布局随版本变化；用错版本的符号表可能不报错但读出错误结果，比直接失败更危险。`banner` 里的版本串是匹配依据。
- **dbg 包是符号来源**：Debian/Ubuntu 的 `linux-image-<ver>-dbg` 包内含 `/usr/lib/debug/boot/vmlinux-<ver>` 与 `System.map-<ver>`；没有调试包时（或自定义内核）需要从同版本内核源码/构建产物生成 DWARF，难度更高。
- **dwarf2json 的位置**：可在 Linux 或 WSL 中运行；生成的 JSON 直接放入 Vol3 源码树的 `framework/symbols/linux/`（或用 `--symbol-dirs` 指定目录），Vol3 启动时自动加载并以文件名匹配内核版本。

## 触发条件

- 已获取 Linux 内存镜像（raw/LiME 等），且 `python3 vol.py -f <image> banner` 能读出内核版本。
- 目标内核没有随 Vol3 发布、也未被本地缓存匹配的 ISF 符号表（否则 Vol3 会提示下载失败/无符号）。
- 能访问发行版安全仓库下载对应 debug 包（或已有同版本 dbg/deb 包）；离线环境需提前准备。
- 有可运行 dwarf2json 的 Linux/WSL 环境；镜像文件可读。

## 利用步骤

1. 读内核版本：
   ```
   python3 vol.py -f flag.mem banner
   ```
   例：`Linux version 5.4.0-100-generic (Ubuntu 5.4.0-100.113-generic)`、`Linux version 5.10.0-21-amd64 (Debian 5.10.162-1)`。
2. 确认发行版与版本号（可用内核支持列表对照表判断是 Ubuntu 20.04 还是 Debian 11），到发行版仓库找到同版本 debug 包（如 `linux-image-5.10.0-21-amd64-dbg_5.10.162-1_amd64.deb`，数百 MB）。
3. 解包并取出调试文件：
   ```
   dpkg-deb -x linux-image-5.10.0-21-amd64-dbg_5.10.162-1_amd64.deb ./dbg
   # 或 ar x 后 tar -xvf data.tar ./usr/lib/debug/boot/
   tar -xvf data.tar ./usr/lib/debug/boot/
   ```
   得到 `System.map-5.10.0-21-amd64`、`vmlinux-5.10.0-21-amd64`。
4. 生成 ISF JSON：
   ```
   dwarf2json linux \
     --system-map /path/usr/lib/debug/boot/System.map-5.10.0-21-amd64 \
     --elf /path/usr/lib/debug/boot/vmlinux-5.10.0-21-amd64 \
     > linux-image-5.10.0-21-amd64-dbg_5.10.162-1_amd64.json
   ```
5. 放入符号目录：
   ```
   sudo mv linux-image-5.10.0-21-amd64-dbg_5.10.162-1_amd64.json \
     /path/volatility3/framework/symbols/linux/
   ```
6. 运行插件验证：
   ```
   python3 vol.py -f oh-my-linux.mem linux.pslist
   python3 vol.py -f oh-my-linux.mem linux.bash
   ```
   `linux.pslist` 能列出 systemd/kthreadd 等进程、`linux.bash` 能恢复命令历史即说明符号表可用。

## PoC

原文实测命令（Debian 11 / 5.10.0-21-amd64 案例）：

```text
python3 vol.py -f oh-my-linux.mem banner
# Linux version 5.10.0-21-amd64 (debian-kernel@lists.debian.org) #1 SMP Debian 5.10.162-1

tar -xvf data.tar ./usr/lib/debug/boot/
# ./usr/lib/debug/boot/System.map-5.10.0-21-amd64
# ./usr/lib/debug/boot/vmlinux-5.10.0-21-amd64

dwarf2json linux \
  --system-map /mount/usr/lib/debug/boot/System.map-5.10.0-21-amd64 \
  --elf /mount/usr/lib/debug/boot/vmlinux-5.10.0-21-amd64 \
  > linux-image-5.10.0-21-amd64-dbg_5.10.162-1_amd64.json

sudo mv linux-image-5.10.0-21-amd64-dbg_5.10.162-1_amd64.json \
  /path/volatility3/framework/symbols/linux/

python3 vol.py -f oh-my-linux.mem linux.pslist
python3 vol.py -f oh-my-linux.mem linux.bash
```

Ubuntu 案例（5.4.0-100-generic）：需先在与镜像同版本内核的 Ubuntu 20.04 环境中构建 Vol2 profile（见关联卡），Vol2 的 `--info` 能列出 `LinuxUbuntu20_5-4-0-100x64` 即 profile 可用。

## 变体与关联

- **Vol2 profile 制作**：`module.c` + `MODULE_LICENSE("GPL")` + `dwarfdump` 生成 module.dwarf，配 `System.map` 打包 zip 放入 overlays（库内已有专卡）；Vol3 的 dwarf2json 是同一目的的另一条工具链。
- **同版本内核环境准备**：镜像内核与当前系统不一致时，需要 `apt-get install linux-image-<ver>-generic linux-headers-<ver>-generic`，并用 `GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux <ver>"` + `update-grub` 切换到目标内核后再构建（原文 Ubuntu 案例的步骤）。
- **其它符号来源**：Ubuntu `ddebs.ubuntu.com` 的 dbgsym 包、自编译内核的 `vmlinux`、`/proc/kallsyms`（运行中主机）等；Windows 镜像则是 PDB 符号（Vol3 自动下载）。
- **地址空间问题**：raw 转储可能报 `No suitable address space mapping`，LiME 分段镜像可正常建立地址空间（库内已有专卡）。

## 检测与防御

- **取证可靠性**：符号表版本必须与 `banner` 完全一致；生成后用 `linux.pslist`/`linux.bash` 做 sanity check，结果异常先怀疑版本不匹配而非镜像损坏。
- **证据链**：在副本上操作，记录镜像与 dbg 包哈希；dbg 包来源记录（发行版仓库 URL/版本），保证可复现。
- **对抗视角**：攻击者可能使用自定义内核/裁剪内核，使标准 dbg 包不匹配；此时需从目标 `/boot` 或源码构建符号，或在采集时保存 `/boot`、`/proc/kallsyms`、`/lib/modules`。
- **防御建议**：应急响应预案中预置常见发行版内核的 ISF 符号表缓存，避免断网时无法分析；对关键服务器的内核版本变更做资产记录。

## 备注

- 原文为 CTF 取证记录（强网杯/0xGame），命令与输出均来自截图；未在本环境复跑。
- 原文引用的内核支持列表是 Trend Micro Deep Security 的兼容表，仅用于确认发行版/版本，非唯一来源。
- 原文 Ubuntu 案例中 `GRUB_DEFAULT` 示例文本写的是 4.15.0-76（笔误），实际切换目标为 5.4.0-100-generic，按上下文理解。
