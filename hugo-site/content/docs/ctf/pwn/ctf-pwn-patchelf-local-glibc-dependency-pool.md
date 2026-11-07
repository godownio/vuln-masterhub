---
id: ctf-pwn-patchelf-local-glibc-dependency-pool
title: 本地 glibc 环境修补：从 libc 提取版本、复制 ld/依赖并 patchelf 递归改 NEEDED
type: scenario
domain: ctf
path: ctf/pwn
technique: patchelf-local-glibc-pool
tags:
- ctf
- pwn
- glibc
- patchelf
- interpreter
- needed
- ld
- environment
- automation
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:54:35+08:00'
  notes: 已对照原文 auto_patch_glibc.sh 核对：strings 提取 release version、版本池精确/最近 major.minor、按 readelf Machine 选 ld 名称、复制 libc/ld、patchelf --set-interpreter 与 --replace-needed、basename/SONAME 映射、递归补 NEEDED 直到闭包稳定、--print-interpreter/--print-needed 验证；卡片为骨架简化且已标注。属本地环境工具卡，未执行。原文无组件版本区间，未设 affected_versions；frontmatter无sources/source_url。
url: /docs/ctf/pwn/ctf-pwn-patchelf-local-glibc-dependency-pool/
draft: false
kb_aliases:
- auto_patch_glibc
- patchelf 改 interpreter
- 本地 libc 依赖修补
- glibc 版本池
- NEEDED 递归替换
- pwn 环境搭建
---

## 一句话结论

拿到题目 binary 和对应 `libc.so.6` 后，可从 libc 字符串提取 glibc 版本，在本地 glibc 版本池中找到精确或最接近的版本目录，复制该版本的 `ld` 与缺失的依赖库到 binary 目录，再用 `patchelf` 把 interpreter 和所有本地 ELF 的 `NEEDED` 改成 `./` 相对路径，从而让 binary 稳定运行在题目指定的 libc 上。

## 原理

- pwn 题的堆布局、`main_arena`/`_IO_*`/`setcontext` 偏移都与 libc 版本强相关；用系统 libc 运行会导致偏移错误、符号缺失或直接崩溃。
- `patchelf --set-interpreter ./ld-linux-x86-64.so.2` 把 ELF 的程序解释器改成同目录的 ld；`patchelf --replace-needed <old> ./<new>` 把动态依赖改成同目录的库文件，避免运行时去系统路径找错版本。
- glibc 版本可从 libc 内的字符串 `GNU C Library (Ubuntu GLIBC 2.35-...) stable release version 2.35.` 提取；也可从文件名/目录名推断。
- 不同架构的 loader 名称不同：x86-64 为 `ld-linux-x86-64.so.2`，i386 为 `ld-linux.so.2`，AArch64 为 `ld-linux-aarch64.so.1`，ARM 为 `ld-linux-armhf.so.3`；需按 `readelf -h` 的 Machine 字段选择。
- 依赖修补需要递归：先收集 binary 目录内所有本地 ELF 的 basename 与 SONAME，建立映射；对每个 ELF 的 `NEEDED`，优先匹配本地文件，其次匹配 libc/ld，再从版本池复制同名库；复制后重新扫描，直到没有新增依赖。
- 版本池通常按 `major.minor` 目录组织（如 `2.35/`、`2.31/`）；找不到精确版本时选最接近的 major.minor，但要注意 ABI 差异，尽量使用题目自带 libc。

## 触发条件

- 题目提供 `libc.so.6`，但缺少匹配的 `ld` 或依赖库；
- 本机系统 glibc 与题目版本不同，直接运行 binary 会偏移错误/崩溃；
- 有本地 glibc 版本池（glibc-all-in-one、各版本 libc 目录）和 `patchelf`；
- 仅在本地分析/调试环境使用，不用于修改目标服务器文件。

## 利用步骤

1. 从 libc 提取版本：`strings -a libc.so.6 | sed -nE 's/.*release version ([0-9]+\.[0-9]+).*/\1/p' | head -1`。
2. 在版本池中找精确 `major.minor` 目录；没有再找最接近版本。
3. 用 `readelf -h binary` 取 Machine，选择对应 loader 名称。
4. 把 libc 与 loader 复制到 binary 目录（保持文件名/SONAME）。
5. 收集 binary 目录内所有 ELF 的 basename 与 SONAME，建立本地映射。
6. 遍历每个 ELF 的 `NEEDED`：本地有则改为 `./name`；缺则从版本池复制同名库后再改；重复直到无新增依赖。
7. `patchelf --set-interpreter ./<ld> binary`，并对所有本地 ELF 执行 `--replace-needed`。
8. 验证：`patchelf --print-interpreter`、`patchelf --print-needed`、`ldd ./binary`，再运行 binary 确认 libc 版本与偏移正确。

## PoC

核心命令骨架（非完整脚本）：

```bash
# 1) 提取 glibc 版本
ver=$(strings -a libc.so.6 | sed -nE 's/.*release version ([0-9]+\.[0-9]+).*/\1/p' | head -1)

# 2) 选版本目录（精确或最接近）
pool=/path/to/glibc-pool
dir=$pool/$ver
[ -d "$dir" ] || dir=$(find "$pool" -maxdepth 1 -type d -name '[0-9]*.[0-9]*' | sort -V | tail -1)

# 3) 按架构选 loader
machine=$(readelf -h ./pwn | sed -nE 's/^[[:space:]]*Machine:[[:space:]]*(.*)$/\1/p')
case "$machine" in
  *X86-64*) ld=ld-linux-x86-64.so.2 ;;
  *80386*)  ld=ld-linux.so.2 ;;
  *AArch64*) ld=ld-linux-aarch64.so.1 ;;
  *ARM*)    ld=ld-linux-armhf.so.3 ;;
esac

# 4) 复制 libc 与 ld
cp -f libc.so.6 "$(dirname ./pwn)/"
cp -f "$dir/$ld" "$(dirname ./pwn)/"

# 5) 改 interpreter
patchelf --set-interpreter "./$ld" ./pwn

# 6) 递归补 NEEDED（示意）
for obj in ./pwn ./*.so*; do
  [ -f "$obj" ] || continue
  patchelf --print-needed "$obj" 2>/dev/null | while read -r need; do
    [ -f "./$(basename "$need")" ] && patchelf --replace-needed "$need" "./$(basename "$need")" "$obj"
  done
done

patchelf --print-interpreter ./pwn
patchelf --print-needed ./pwn
```

完整脚本还会从版本池复制缺失依赖、按 SONAME 建映射并循环扫描，直到依赖闭包稳定。

## 变体与关联

- 变体：使用 `pwninit` 自动完成 libc/ld 复制与 patchelf；或用 Docker 镜像固定发行版/glibc 版本。
- 变体：用 `patchelf --set-rpath '$ORIGIN'` 让 loader 从 binary 目录找库，减少逐个 `--replace-needed`。
- 变体：`LD_LIBRARY_PATH=.` + 直接调用 `./ld --library-path . ./pwn`，不改 binary 也能运行指定 libc（但某些场景 patchelf 更稳）。
- 关联：pwn 环境搭建、libc 版本识别、堆偏移计算、AWD 批量利用。
- 边界：只改本地副本；不要对目标服务器上的系统库执行 patchelf；版本池中的“最接近版本”仍可能有 ABI 差异，优先使用题目自带 libc。

## 检测与防御

- 该卡是本地分析与环境搭建技术，不针对远程目标；防御侧无需专门检测。
- 若在共享环境使用，注意不要覆盖系统 `/lib`/`/usr/lib` 下的库；只在题目目录内使用 `./` 相对路径。
- 对比赛/靶场：保留原始 binary/libc 的哈希，修补后的副本单独存放，避免污染证据。
