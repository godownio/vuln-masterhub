---
id: defense-forensics-elf-constructor-order-dt-needed
title: ELF 构造器顺序取证：DT_NEEDED 顺序不等于实际初始化顺序
type: scenario
domain: defense
path: defense/forensics
technique: elf-constructor-order-cross-dso
tags:
- linux
- forensics
- elf
- constructor
- dt-needed
- init-array
- ld-preload
- dynamic-linker
- ld-debug
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V97
  verified_at: '2026-11-05T19:38:27+08:00'
  notes: 已对照原文与17张图核对：DT_NEEDED 顺序（图5）与 LD_DEBUG 实际 init 顺序（图8、13）矛盾、.init_array 地址映射（图6）、链接顺序对照 app_wr/app_rw（图9/11）、LD_PRELOAD 构造器晚于普通依赖（图13）均与原文一致；AT_SECURE 下 LD_DEBUG 失效的边界正确。未验证点：未实际编译执行；frontmatter 无 sources/source_url。
url: /docs/defense/forensics/defense-forensics-elf-constructor-order-dt-needed/
draft: false
kb_aliases:
- DT_NEEDED 构造器顺序
- constructor 优先级跨 DSO
- init_array 顺序
- LD_DEBUG=libs 顺序
- LD_PRELOAD 构造器
- 依赖图拓扑序
---

## 一句话结论

`DT_NEEDED` 的文本顺序只影响加载列表与符号查找，不能据此推断构造器执行顺序；`__attribute__((constructor(N)))` 的优先级只在单个 ELF 对象内有效，跨共享对象由动态链接器按依赖图初始化，`LD_PRELOAD` 对象的构造器也不保证最早执行；取证与安全设计必须用 `LD_DEBUG=libs` 或实际运行日志确认顺序。

## 原理

- 动态链接器先构建依赖图，再按自己的拓扑处理顺序调用各对象的初始化函数；`DT_NEEDED` 是每个对象的直接依赖清单，文本排列顺序会参与加载/符号查找，但不定义跨对象的全局构造器顺序。
- `__attribute__((constructor(N)))` 在单个 ELF 对象内被编译进 `.init_array`，按优先级与链接顺序排列；不同共享对象各自的 `101`、`65534` 之间没有全局比较语义，不能推出“数字小的一定先在别的库之前执行”。
- `.init_array` 的内容是函数指针数组（小端），可用 `readelf -W -x .init_array` 读出地址，再用 `nm -an` 对应到具体构造器与编译器插入的 `frame_dummy`。这只能证明单对象内部顺序。
- `LD_PRELOAD` 对象在符号解析阶段拥有较高优先级（可顶替同名符号），但符号绑定与构造器调用是两个阶段；实测预加载对象的构造器可能晚于普通 `DT_NEEDED` 依赖的构造器。
- 因此“按 `DT_NEEDED` 顺序执行”“优先级小的全局先跑”“`LD_PRELOAD` 一定最早”都是不可靠假设。依赖构造器顺序的安全初始化（环境清洗、seccomp 安装、完整性校验）可能被更早执行的其他对象绕过或干扰。

## 触发条件

- 进程包含多个带构造器的共享对象（主程序、`DT_NEEDED` 依赖、`LD_PRELOAD` 对象、`dlopen` 插件）。
- 需要确定实际初始化顺序，或安全机制的设计假设依赖某个构造器先执行。
- 可在受控环境重放启动；`LD_DEBUG` 在 `AT_SECURE`（setuid/setgid）程序下会被加载器忽略，此时需改用静态分析或运行时跟踪。

## 利用步骤

1. 记录依赖：`readelf -d ./app | grep -E 'NEEDED|RPATH|RUNPATH'`，得到 `DT_NEEDED` 文本顺序。
2. 查看单对象构造器表：`readelf -W -x .init_array ./libwriter.so`，再用 `nm -an ./libwriter.so | grep -E 'ctor|frame_dummy'` 把条目地址映射到符号；确认对象内部的优先级顺序。
3. 获取实际跨对象顺序：`LD_DEBUG=libs ./app 2>&1 >/dev/null | grep -E 'calling init|initialize program|transferring control|calling fini'`；必要时用 `LD_DEBUG=files` 看加载与初始化。
4. 做最小对照：只改变链接参数（例如 `-lwriter -lreader` 与 `-lreader -lwriter`）重新编译两个主程序，比较首个构造器来自哪个库，排除 `main`、`dlopen`、`LD_PRELOAD` 的干扰。
5. 做 `LD_PRELOAD` 对照：`LD_PRELOAD=./libpre.so LD_DEBUG=libs ./app`，观察预加载对象构造器在初始化序列中的实际位置。
6. 将静态 `DT_NEEDED`/`.init_array` 与动态 `LD_DEBUG` 结果并列记录；若两者矛盾，以实际运行顺序为准，并检查是否还有 `dlopen` 或 IFUNC resolver 等更早阶段。

## PoC

```bash
# 1) DT_NEEDED 文本顺序（示例：writer 在 reader 前）
readelf -d ./app_wr | grep -E 'NEEDED|RUNPATH'

# 2) 单对象 .init_array 与构造器符号
readelf -W -x .init_array ./libwriter.so
nm -an ./libwriter.so | grep -E 'writer_ctor|frame_dummy'
# 例：f3 15 00 00 00 00 00 00 -> 0x15f3 = writer_ctor_101
#     68 16 00 00 00 00 00 00 -> 0x1668 = writer_ctor_last
#     0x11e0 = frame_dummy（编译器插入）

# 3) 实际初始化顺序：app_wr 的 NEEDED 虽 writer 在前，
#    但 LD_DEBUG 显示 libreader.so 的 init 先于 libwriter.so
LD_DEBUG=libs ./app_wr 2>&1 >/dev/null \
  | grep -E 'calling init|initialize program|transferring control|calling fini'

# 4) 只改链接顺序的对照：app_rw 的首个构造器变为 writer
readelf -d ./app_rw | grep NEEDED
LD_DEBUG=libs ./app_rw 2>&1 >/dev/null \
  | grep -E 'calling init|initialize program|transferring control'

# 5) LD_PRELOAD 对象构造器不一定最早
LD_PRELOAD=./libpre.so LD_DEBUG=libs ./app_wr 2>&1 >/dev/null \
  | grep -E 'calling init|initialize program|transferring control'
```

```c
/* 构造器优先级只在单对象内生效的示意 */
__attribute__((constructor(101)))  static void a(void) { /* ... */ }
__attribute__((constructor(65534))) static void b(void) { /* ... */ }
/* 共享对象 B 里的 constructor(101) 与对象 A 的 65534 无全局先后语义 */
```

## 变体与关联

- 变体：IFUNC resolver 在重定位阶段执行，比所有构造器都早，可用于绕过“构造器先装 seccomp”的假设。
- 变体：`.preinit_array` 仅主可执行文件支持，理论上先于其他初始化，但不应作为通用安全边界；`dlopen` 的对象构造函数在加载时执行，顺序更晚。
- 变体：`RTLD_NOW`/`RTLD_LAZY`、`-Wl,-z,now` 改变符号绑定时机，不等于改变构造器调用顺序。
- 关联：[[defense-forensics-proc-environ-startup-view-split]]（同一实验的环境视图结论）、[[binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp]]（IFUNC 早于 constructor 的绕过）、[[defense-forensics-ifunc-resolver-triage]]（IFUNC 行为取证）、[[pentest-privilege-escalation-ld-preload-symbol-interposition-downgrade]]（LD_PRELOAD 构造器代码执行）。
- 边界：不同 glibc/动态链接器版本的初始化顺序可能不同；`LD_DEBUG` 在 setuid/AT_SECURE 下不可用；静态链接或 `-Bsymbolic` 会改变符号解析，需单独分析。

## 检测与防御

- 取证：不要用 `readelf -d` 的 `DT_NEEDED` 顺序推断构造器先后；同时采集 `.init_array`（单对象内顺序）与 `LD_DEBUG=libs`（实际跨对象顺序），必要时用 `strace`/调试器在 `__libc_start_main` 前后观察。
- 防御：安全初始化不要放在依赖顺序的构造器里。把 seccomp、环境清洗、完整性校验放在独立 launcher/父进程于 `exec` 前完成，或在 `main` 开头显式执行；插件/不受信任 DSO 应在独立进程加载。
- 检测：监控 `LD_PRELOAD`/非标准路径 DSO 的加载；审计是否存在“安全构造器先于不可信对象构造器”的假设；用 `LD_DEBUG=libs` 建立正常版本初始化顺序基线，异常顺序作为调查线索。
