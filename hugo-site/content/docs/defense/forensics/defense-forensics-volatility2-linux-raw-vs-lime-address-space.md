---
id: defense-forensics-volatility2-linux-raw-vs-lime-address-space
title: Volatility2 解析 Linux 内存镜像：raw 转储报 No suitable address space mapping，LiME 分段头格式可正常建立地址空间
type: scenario
domain: defense
path: defense/forensics
technique: volatility2-linux-address-space-lime
tags:
- linux
- forensics
- memory
- volatility2
- lime
- raw
- address-space
- acquisition
- incident-response
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V363
  verified_at: '2026-11-09T03:17:29+08:00'
  notes: 已对照原文与截图核对：raw 镜像 linux_cpuinfo 报 No suitable address space mapping found 并逐项列出地址空间候选失败（截图 07，命令含 -f linux.raw）；LiME 镜像 linux_cpuinfo 列出 Processor 0-15（截图 04）、linux_psscan 列出进程但 Uid/Gid/DTB 为空（截图 05/06），与卡片描述一致。未验证点：原文 --info 截图的 profile 名 Linuxuxlinux_centos8_5_kernel_4_18x64 与命令中 --profile=Linuxcentos8x64 不一致，属原文自身不一致；卡片沿用命令中的名字，按 medium 置信度保留。
url: /docs/defense/forensics/defense-forensics-volatility2-linux-raw-vs-lime-address-space/
draft: false
kb_aliases:
- LiME 格式
- lime 内存镜像
- raw 镜像无法识别
- No suitable address space mapping
- LinuxAMD64PagedMemory 失败
- 内存镜像格式选择
---

## 一句话结论

Volatility2 打开 Linux raw 内存转储时会依次尝试所有地址空间类并全部失败，报 `No suitable address space mapping found`；改用 LiME 格式采集（每段物理内存前带固定头部，头部记录该段起始/结束物理地址等元数据）后，Volatility2 能直接建立地址空间映射，配合自建 profile 可识别 CPU 核心数并用 `linux_psscan` 列出进程，因此 Linux 内存取证应优先使用 LiME 采集。

## 原理

- **地址空间自动探测**：Volatility2 打开镜像时按候选顺序尝试各类 AddressSpace（WindowsCrashDump、LimeAddressSpace、VMwareMetaAddressSpace、QemuCoreDump、LinuxAMD64PagedMemory 等），每一类都要通过签名/头部校验和“地址空间有效性检查”（valid Address Space check）。全部候选失败才输出 `No suitable address space mapping found` 及其逐项失败原因。
- **raw 为什么容易失败**：raw 只是物理内存的线性拼接，文件本身不含任何元数据。Volatility2 只能借助 profile 与 `LinuxAMD64PagedMemory` 按页表结构去推断物理→虚拟映射；一旦 profile 与镜像内核/采集方式不能严格对应，有效性检查失败（错误清单中可见 `LinuxAMD64PagedMemory: Failed valid Address Space check`），而其他类又因无签名或 profile 不兼容（如 `Incompatible profile ... selected`）失败，最终没有任何可用地址空间。
- **LiME 为什么能解析**：LiME 是内核模块采集工具，写盘时对每个物理内存 range 先写一个固定大小的头部，包含 magic、版本、该 range 的起始与结束物理地址、保留字段，随后才是该 range 的数据。Volatility2 的 `LimeAddressSpace` 按头部遍历各 range，能直接知道每段数据对应的物理地址区间，不需要猜页表，因此同样内核、同一个自建 profile 下，raw 失败而 LiME 可以建立地址空间。
- **能到哪一步**：地址空间建立后，`linux_cpuinfo` 能列出 Processor 0..N（CPU 核心数可识别），`linux_psscan` 能枚举进程（Offset/Name/Pid/PPid）。自建 profile 下部分字段仍可能为空（cpuinfo 的 Vendor/Model、psscan 的 Uid/Gid/DTB），这是 profile 完整度/插件兼容问题，不影响“地址空间已成功解析”的判定。

## 触发条件

- 已有 Linux 内存镜像，用 Volatility2 分析时报 `No suitable address space mapping found`。
- 同时已经按目标内核构建了 profile（否则 LiME 镜像也会因 `Incompatible profile` 失败）；profile 制作见关联卡片。
- 能向目标机（或同内核可加载 LiME 的环境）加载与 `uname -r` 匹配的 `lime-<版本>.ko`，具备 root 与 insmod 权限。
- 采集前已记录内核版本、采集工具与参数，用于事后复现。

## 利用步骤

1. **判定问题在格式而非 profile**：保留 Volatility2 的完整报错清单，确认所有地址空间候选都失败、且其中包含 `LinuxAMD64PagedMemory: Failed valid Address Space check`；若同时怀疑 profile，先用 `vol.py --info` 确认 profile 名存在且来自同内核版本。
2. **改用 LiME 采集**：把与目标内核版本匹配的 `lime-<uname -r>.ko` 上传到目标机，以 root 执行 `insmod lime-<版本>.ko "path=<输出路径> format=lime"`，等待写盘完成后记录文件大小与哈希。
3. **用同一 profile 打开 LiME 镜像**：`vol2 -f <lime 镜像> --profile=<profile 名> linux_cpuinfo`，能看到 Processor 0..N 即说明地址空间已建立。
4. **验证进程枚举**：`vol2 -f <lime 镜像> --profile=<profile 名> linux_psscan`，检查是否列出 systemd/kworker 等进程；Uid/Gid/DTB 为空属已知局限，用 Name/Pid/PPid/Offset 做后续分析。
5. **记录证据链**：保存 LiME 模块版本、insmod 参数（尤其 `format=lime` 与 path）、镜像哈希、profile 名与 Volatility2 版本。

## PoC

```bash
# 目标机：LiME 采集（root，模块版本需与 uname -r 一致）
insmod lime-4.18.0-348.7.1.el8_5.x86_64.ko "path=/root/mem/linux.mem format=lime"

# 分析机：用自建 profile 解析 LiME 镜像
vol2 -f linux.mem --profile=Linuxcentos8x64 linux_cpuinfo
vol2 -f linux.mem --profile=Linuxcentos8x64 linux_psscan
```

raw 镜像失败时的典型输出（节选）：

```text
No suitable address space mapping found
Tried to open image as:
 ...
 LinuxAMD64PagedMemory: Failed valid Address Space check
 SkipDuplicatesAMD64PagedMemory: Incompatible profile Linuxcentos8x64 selected
```

## 变体与关联

- **padded 格式**：Volatility2 还内置 padded 地址空间（针对带填充的原始转储），LiME 不可用时可尝试；能否解析取决于采集工具输出的实际布局与 profile。
- **profile 制作**：地址空间建立的前提是 profile 与镜像内核一致，构建流程与 dwarfdump 兼容坑见 [[defense-forensics-volatility2-linux-profile-build-module-dwarf-systemmap]]。
- **Windows 对比**：Windows 的 crash dump/hiberfil 等有专门地址空间类可识别；Linux raw 缺少页表/头部元数据，是 `No suitable address space mapping` 的高发场景。
- **采集完整性**：LiME 按 range 记录物理地址，采集日志/range 列表应一并保存；缺失 range 会让部分结构落在镜像之外，影响后续插件结果。

## 检测与防御

- **取证规范**：Linux 内存优先用 LiME（lime 格式）采集；采集前记录 `uname -r`、模块版本、insmod 参数，避免事后因格式问题重采。
- **一致性检查**：profile、System.map、module.dwarf 三者必须与镜像内核一致；地址空间失败或插件结果异常时先核对版本，而不是只换分析命令。
- **结果判读**：自建 profile 下 `linux_cpuinfo` 的 Vendor/Model、`linux_psscan` 的 Uid/Gid/DTB 可能为空，只使用已验证字段并与其他主机证据交叉。
- **检测视角**：加载 LiME 内核模块、读取物理内存并写出大文件的行为会留下模块加载审计与文件痕迹；非授权内存采集可作为入侵/内部威胁的调查线索。
