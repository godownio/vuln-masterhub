---
id: defense-forensics-ifunc-resolver-triage
title: IFUNC resolver 行为取证：readelf、strace 与 LD_DEBUG 判定加载期执行
type: scenario
domain: defense
path: defense/forensics
technique: ifunc-resolver-triage
aliases:
- 判断 IFUNC 是否执行
- resolver 取证
- readelf IFUNC
- LD_DEBUG reloc
- strace 启动顺序
- 加载期执行点排查
tags:
- linux
- forensics
- elf
- ifunc
- ld-debug
- strace
- incident-response
- dynamic-linker
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:54:24+08:00'
  notes: 已对照原文与图01-16核对：符号/重定位/BIND_NOW/strace/LD_DEBUG/ldd 四路取证与原文一致；lazy 模式抓不到启动 syscall 的边界已写明；未复跑
---

## 一句话结论

可疑进程在 constructor 或 `main` 之前出现 syscall/文件落地时，用 `readelf` 查 IFUNC 符号与重定位/绑定模式、`strace` 看启动 syscall 顺序、`LD_DEBUG=reloc` 看重定位处理、`ldd`/环境变量查 preload，四路证据即可判断行为是否来自 IFUNC resolver。

## 原理

- IFUNC resolver 由动态链接器在重定位期调用，早于 `DT_INIT`/构造函数和 `main`；它执行时进程的 libc 复杂设施尚未就绪，因此恶意行为通常表现为“最早的裸 syscall（write/openat/execve）”。
- 判断需要回答四个问题，每个问题对应一条证据：
  1. **有没有 IFUNC**：`readelf -sW <bin> | grep IFUNC`；没有 IFUNC，可疑行为更可能来自构造函数或普通符号覆盖。
  2. **有没有被引用**：`readelf -rW <bin> | grep -E 'IRELATIVE|JUMP_SLOT'`；IFUNC 符号存在但无重定位引用时 resolver 不会执行（未命中分支）。
  3. **什么时候绑定**：`readelf -d <bin> | grep BIND_NOW`；IRELATIVE 永远加载期；JUMP_SLOT 默认 lazy（首次调用），BIND_NOW/`LD_BIND_NOW=1` 则加载期。lazy 目标用 strace 抓启动 syscall 可能“抓不到”，不能据此排除。
  4. **是谁注入的**：`ldd <bin>` 看非系统路径库、`/etc/ld.so.preload`、环境中的 `LD_PRELOAD`/`LD_LIBRARY_PATH`。

## 触发条件

- 已获得可疑二进制、运行环境或现场内存/进程信息；
- 能在受控环境重放启动过程，或有启动期 syscall 审计日志（auditd/eBPF/strace）；
- 非 `AT_SECURE` 场景才能用 `LD_DEBUG`；setuid 程序会忽略该变量，需要静态分析或系统级审计；
- 有正常基线可对比（同一程序的依赖、绑定模式、启动 syscall 顺序）。

## 利用步骤

1. **符号层**：`readelf -sW <bin> | grep -i ifunc`，记录 IFUNC 符号名与所在库；`readelf -rW <bin> | grep -E 'IRELATIVE|JUMP_SLOT'`，确认重定位引用。
2. **绑定层**：`readelf -d <bin> | grep -E 'BIND_NOW|FLAGS|FLAGS_1'`；判断 resolver 是加载期还是首次调用。
3. **时序层**：`strace -f -e trace=write,openat,execve,close ./<bin>`，看可疑 syscall 是否排在构造函数/`main` 之前；也可用 `LD_DEBUG=reloc ./<bin> 2>&1 | grep -i ifunc` 观察重定位处理。
4. **来源层**：`ldd <bin>`、`cat /etc/ld.so.preload`、检查进程环境 `LD_PRELOAD`/`LD_LIBRARY_PATH`/`LD_BIND_NOW`；对比基线环境的库列表。
5. **静态二进制**：`readelf -sW <bin> | grep IFUNC | wc -l`，静态链接的程序 IFUNC 数量通常远多于动态程序；resolver 由启动代码更早执行。
6. 汇总：四路证据同时指向“某依赖库的同名 IFUNC + 预加载来源 + 加载期 syscall”，即可确认是 IFUNC 重定向；若只有构造函数执行，则不是本条链。

## PoC

```bash
# 1) 符号与重定位
readelf -sW libfoo.so | grep IFUNC
readelf -rW ifunc_basic | grep IRELATIVE
readelf -rW prog | grep JUMP_SLOT | grep fn

# 2) 绑定模式
readelf -d prog | grep BIND_NOW || echo "prog: lazy"
readelf -d prog_now | grep BIND_NOW

# 3) 时序：resolver 的 write/openat 应最早出现
strace -f -e trace=write,openat,close ./prog_now 2>&1 | head -8
# write(2, "[evil-sys-resolver]...")  → openat("/tmp/ifunc_pwned_sys.txt") → ctor → main

# 4) 注入来源
ldd ./prog_now
cat /etc/ld.so.preload 2>/dev/null
env | grep -E 'LD_PRELOAD|LD_LIBRARY_PATH|LD_BIND_NOW'
```

## 变体与关联

- `LD_DEBUG=reloc` 能看到重定位处理过程；`LD_DEBUG=files` 看加载列表；两者在 `AT_SECURE` 下都失效。
- 静态链接程序没有动态链接器，但 IFUNC 仍由启动代码执行；需用 `readelf` 与启动 syscall 审计判断。
- 普通符号覆盖只改 GOT 数据、不执行攻击者代码；若要区分，重点看是否有 resolver 的早期 syscall。
- 关联卡片：[[code-analysis-reverse-linux-ifunc-symbol-hijack-resolver]]、[[binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp]]、[[defense-hardening-ifunc-resolver-injection]]。

## 检测与防御

- 检测：对关键二进制建立 IFUNC 清单与 BIND_NOW 基线；CI 对构建产物做 diff；采集启动期 syscall（auditd `execve`/`openat`、eBPF）并关联加载库来源；监控非系统路径库与 `/etc/ld.so.preload` 变更。
- 防御：`AT_SECURE`、静态链接、隐藏 IFUNC 符号、依赖库完整性校验；把安全边界放在 ld.so 之前。
- 注意：lazy 模式下 resolver 可能延迟到首次调用，启动时抓不到；必须结合 `readelf` 的绑定标记判断，不能只看 strace。
