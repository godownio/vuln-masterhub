---
id: defense-hardening-ifunc-resolver-injection
title: IFUNC 重定向的分层防御：AT_SECURE、静态链接、符号隐藏与审计
type: scenario
domain: defense
path: defense/hardening
technique: ifunc-resolver-hardening
aliases:
- 防 IFUNC 劫持
- AT_SECURE 防 preload
- 隐藏 IFUNC 符号
- 静态链接防注入
- IFUNC 清单审计
tags:
- linux
- hardening
- elf
- ifunc
- at-secure
- static-linking
- visibility
- audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:54:27+08:00'
  notes: 已对照原文第六节核对：AT_SECURE 阻断 preload、静态链接消除动态覆盖、符号隐藏、审计与安全边界前置均与原文一致；AT_SECURE 对比实验原文仅文字描述无截图；未复跑
---

## 一句话结论

IFUNC 重定向的防御要分层：`AT_SECURE` 阻断环境变量注入、静态链接消除动态符号覆盖、版本脚本/`hidden` 隐藏 IFUNC 符号、审计负责发现；但每一层都有残余面，最终要防的是“整个库文件被替换”和“`RPATH/RUNPATH` 指向可写目录”这类文件系统/供应链问题。

## 原理

IFUNC resolver 是 ELF 规范留下的“重定位期执行点”：加载器为了取得最终函数地址必须调用用户代码。防御的目标不是消除 IFUNC（glibc 自身大量使用），而是让攻击者无法控制“加载器会调到谁的 resolver”。对应四层：

- **特权上下文 / `AT_SECURE`**：进程 `euid != uid`（setuid/setgid）时内核置 `AT_SECURE`，ld.so 忽略 `LD_PRELOAD`、`LD_LIBRARY_PATH`、`LD_DEBUG`。实测：root 下注入 `fn(21)=63`、落盘；降权用户运行同一程序 `fn(21)=42`、无落盘。它挡不住“root 拥有的库文件被替换”，那属于文件系统/供应链问题。
- **静态链接**：静态程序没有动态链接器，`LD_PRELOAD` 无效；但静态链接把 glibc 的字符串/内存函数全部变成 IFUNC（实测从动态小程序的 1 个涨到 38 个），resolver 由启动代码在 `main` 之前执行，且 libc stdio 尚未就绪（`fprintf` 直接段错误 exit 139）。所以静态链接要配合“自包含 resolver/自定义启动代码”才能作为安全边界。
- **符号可见性控制**：库作者用版本脚本或 `-fvisibility=hidden` 隐藏 IFUNC 导出符号，预加载库无法提供同名定义；但对“替换整个库文件”无效，因为攻击者的库可以直接导出同名符号。
- **检测与审计**：`readelf -sW` 扫 IFUNC、`readelf -d` 看 BIND_NOW、`readelf -rW` 看 IRELATIVE/JUMP_SLOT、`ldd` 与 `/etc/ld.so.preload` 查 preload、`LD_DEBUG=files` 盯启动；CI 对构建产物的 IFUNC 清单做 diff。
- **安全机制前置**：resolver 早于 `seccomp`/沙箱初始化；若安全边界依赖 `main` 之后安装的过滤器，resolver 阶段的恶意 syscall 不会被看到。要防御这一点，应让安全边界在 ld.so 之前介入（静态 PIE + 自定义启动代码、父进程在 exec 前装好 seccomp、外部 LSM/审计）。

## 触发条件

- 防守方拥有二进制/库的构建控制权，或要对现成二进制做加固审计；
- 目标为 ELF 动态链接程序，且依赖库导出或引用 IFUNC；
- 需要同时考虑 setuid/setgid、静态链接、库内部符号与运行期注入；
- 攻击者可能通过环境变量、库文件替换或 `RPATH/RUNPATH` 影响加载。

## 利用步骤

1. **优先消除环境变量注入面**：确保特权程序保持 setuid/setgid 的真实 `AT_SECURE` 状态，不要用 wrapper 先降权再 exec，也不要在启动脚本中保留用户可控的 `LD_PRELOAD`/`LD_LIBRARY_PATH`。
2. **保护库文件与路径**：关键库目录 root 独占、0755；`readelf -d` 审计 `RPATH/RUNPATH`，禁止指向普通用户可写目录；`/etc/ld.so.preload` 仅 root 可写并纳入监控。
3. **隐藏关键 IFUNC 符号**：用版本脚本或 `-fvisibility=hidden`，确认 `readelf --dyn-syms` 中不再导出；注意这只防同名预加载，不防整库替换。
4. **按场景选择静态链接**：对不需要动态插件的高安全组件可静态链接；同时用 raw syscall 实现启动代码、避免 reloc 期依赖 libc；对需要动态加载的组件不要用静态链接当万能解。
5. **把安全边界前置**：seccomp/沙箱/降权必须在 ld.so 之前生效（父进程 exec 前安装、静态 PIE 自定义启动代码、LSM/审计），不要依赖 `main` 或 constructor 中的安装点。
6. **建立审计基线**：CI 扫描 `readelf -sW` 的 IFUNC 清单与 BIND_NOW 标记，产物变化时告警；生产环境采集启动期 syscall 与加载库来源。
7. **回归验证**：对每种加固组合做注入测试，确认 `fn` 结果未被改写、resolver 恶意 syscall 未出现或已被前置防线拦截。

## PoC

```bash
# 1) AT_SECURE：setuid 程序忽略 LD_PRELOAD
su testuser -c 'LD_PRELOAD=./evil.so ./ifunc_prog_suid'   # fn=42，无落盘
sudo LD_PRELOAD=./evil.so ./ifunc_prog                    # root：fn=63，落盘

# 2) 静态链接：LD_PRELOAD 无效
gcc -O0 -static -o ifunc_static ifunc_basic.c
LD_PRELOAD=./evil.so ./ifunc_static                       # resolver 使用自身实现
readelf -sW ifunc_static | grep IFUNC | wc -l             # 38 个 IFUNC

# 3) 隐藏 IFUNC 符号
# libfoo_hidden.c: __attribute__((visibility("hidden"))) int fn(...) __attribute__((ifunc(...)));
readelf --dyn-syms libfoo_hidden.so | grep fn || echo "fn hidden"
# preload 同名库无法命中

# 4) 审计
readelf -sW ./bin | grep -i ifunc
readelf -d ./bin | grep BIND_NOW
readelf -rW ./bin | grep -E 'IRELATIVE|JUMP_SLOT'
ldd ./bin
cat /etc/ld.so.preload 2>/dev/null
```

## 变体与关联

- `AT_SECURE` 只挡环境变量；库替换、`RPATH/RUNPATH`、`/etc/ld.so.preload` 是另外的入口，需要文件权限与供应链控制。
- 静态链接不是普遍适用：插件化/热更新场景仍需动态链接，应改用符号隐藏 + 完整性校验 + 前置安全边界。
- 隐藏符号只防“同名预加载”，不防攻击者直接替换整个 `.so` 文件。
- 关联卡片：[[code-analysis-reverse-linux-ifunc-symbol-hijack-resolver]]、[[binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp]]、[[defense-forensics-ifunc-resolver-triage]]、[[pentest-privilege-escalation-ld-preload-symbol-interposition-downgrade]]。

## 检测与防御

- 检测：IFUNC 清单与 BIND_NOW 基线、非系统路径库加载、`/etc/ld.so.preload` 变更、启动期 syscall 审计、库文件哈希/签名校验。
- 防御：`AT_SECURE`、静态链接（配合自包含启动代码）、符号隐藏、依赖锁定与可复现构建、可写目录 `nosuid`、安全边界前置。
- 注意：单层防护都只堵一条路径；分层后仍要承认“root 库文件被替换”超出加载器能管的范围。
