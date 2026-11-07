---
id: defense-forensics-elf-symbol-interposition-triage
title: ELF 符号顶替的四路取证：dladdr、readelf、LD_DEBUG 与 objdump
type: scenario
domain: defense
path: defense/forensics
technique: elf-symbol-interposition-triage
tags:
- linux
- forensics
- elf
- dynamic-linking
- ld-debug
- symbol-resolution
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:30:01+08:00'
  notes: 已对照原文与19张图核对：dladdr 自报、readelf -d/--dyn-syms（图14 仅 verify_security 导出）、LD_DEBUG=files/bindings（图18/19）、objdump 看 @plt 直连（图20）四路证据与原文一致。未验证点：未实际执行取证命令；frontmatter 无 sources/source_url。
url: /docs/defense/forensics/defense-forensics-elf-symbol-interposition-triage/
draft: false
kb_aliases:
- 符号顶替取证
- 判断函数被哪个库替换
- LD_DEBUG bindings 取证
- dladdr 落点
- readelf dynsyms
- objdump PLT 直连
---

## 一句话结论

怀疑某个函数实现被同名库顶替时，用 `dladdr` 程序自报、`readelf` 动态段、`LD_DEBUG=files/bindings` 加载器日志、`objdump` 机器码四路互不依赖的证据，可以独立坐实“哪个符号最终绑定到了哪个库”。

## 原理

- 符号绑定发生在加载期，程序本身的源码和日志不会说明实现来自哪个库；需要从不同层观察同一次裁决。
- **程序自报**：`dladdr((void *)func_ptr, &info)` 返回该地址所属的共享对象路径，最直接。
- **ELF 动态段**：`readelf -d` 列出 `DT_NEEDED` 顺序与 `RPATH/RUNPATH`；`readelf --dyn-syms` 列出导出符号及其所在对象，可判断“这个库有没有提供同名定义”“主程序有没有把符号导出”。
- **加载器日志**：`LD_DEBUG=files` 打印加载列表与构造函数/析构函数调用顺序；`LD_DEBUG=bindings` 打印每次符号绑定，格式为 `binding file <引用者> to <提供者>: normal symbol '<name>'`，直接给出裁决结果。
- **机器码**：`objdump -d` 看调用点是 `call <symbol@plt>` 还是直连本地地址；走 PLT 才有被外部顶替的可能，直连调用固定在本模块内。
- 四路证据互相独立：任何一路都能指认实现归属，交叉比对可避免“日志里出现同名库但其实没绑定”的误判。

## 触发条件

- 已获取可疑二进制、相关 `.so` 与运行环境；
- 能在受控环境重放启动过程（`LD_DEBUG` 需要非 `AT_SECURE` 场景，setuid/setgid 程序会忽略该变量）；
- 或能在离线环境用 `readelf`/`objdump` 做静态分析；
- 有基线版本可对比（同一程序正常环境下的依赖与绑定结果）。

## 利用步骤

1. **动态段**：`readelf -d <bin> | grep -E "NEEDED|RPATH|RUNPATH"`，记录依赖顺序与库搜索路径；`readelf --dyn-syms <bin> | grep <symbol>` 看符号是否导出。
2. **加载列表**：`LD_DEBUG=files ./<bin> 2>&1 | grep -E "<libA>|<libB>"`，确认实际加载了哪些库、构造函数按什么顺序执行。
3. **绑定落点**：`LD_DEBUG=bindings ./<bin> 2>&1 | grep -F <symbol>`，查看 `binding file ... to ...` 的提供者；带 `LD_PRELOAD` 再跑一次对比。
4. **程序自报**：若程序使用 `dladdr`（或可在调试器中调用），查看函数指针所属 `.so` 路径。
5. **机器码**：`objdump -d <lib> | grep -A3 "<caller>"`，确认内部调用是 `@plt` 还是直连；`@plt` 表示可被外部裁决。
6. **运行期佐证**：检查 `/proc/<pid>/maps` 中加载的库路径，核对是否有非标准目录的 `.so`。
7. 汇总四路结果：若绑定日志、`dladdr`、`readelf` 与业务输出一致指向同一库，即可确认顶替；若不一致，优先检查是否 `AT_SECURE`、是否 `-Bsymbolic`、是否直连调用。

## PoC

```text
# 1) 依赖与搜索路径
readelf -d ./prog_single | grep -E "NEEDED|RPATH|RUNPATH"

# 2) 加载列表与构造顺序
LD_DEBUG=files ./prog_single 2>&1 | grep -E "libA_new|libB_old"

# 3) 符号绑定落点（注入前后对比）
LD_DEBUG=bindings LD_PRELOAD=./libB_old.so ./prog_single 2>&1 | grep -F verify_security
# binding file ./prog_single [0] to ./libB_old.so [0]: normal symbol `verify_security'

# 4) 导出符号
readelf --dyn-syms ./prog_exe | grep -E "verify_security|verify_exe_only"

# 5) 机器码：走 PLT 还是直连
objdump -d ./libA_new.so | grep -A3 "<verify_wrapped>"
# call 1030 <verify_security@plt>
```

## 变体与关联

- `LD_DEBUG` 在 `AT_SECURE`（setuid/setgid）下被加载器忽略，此时只能用 `readelf`/`objdump` 静态取证或从 `/proc/<pid>/maps`、审计日志侧面确认。
- `dladdr` 需要程序自身支持或借助调试器调用；没有符号的程序可改用 `LD_DEBUG=bindings`。
- 关联卡片：[[pentest-privilege-escalation-ld-preload-symbol-interposition-downgrade]]、[[pentest-privilege-escalation-dt-needed-symbol-order-hijack]]、[[defense-hardening-elf-symbol-interposition-mitigation]]。

## 检测与防御

- 检测：对关键二进制建立依赖与导出符号基线；监控非系统路径 `.so` 的加载；采集 `LD_DEBUG=bindings` 或 auditd `mmap` 事件；比对 `/proc/<pid>/maps` 与基线。
- 防御：固定库路径与依赖顺序、哈希/签名校验、限制可写 `RPATH/RUNPATH` 目录、启动前清洗 `LD_PRELOAD`/`LD_LIBRARY_PATH`。
- 注意：取证时应在受控副本上进行，避免 `LD_DEBUG` 输出过大影响生产；不要把业务输出本身当作唯一证据。
