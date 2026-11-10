# 浏览器利用

## 这层是什么

JIT、渲染引擎、沙箱与逃逸。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [J2V8 老版本 V8（9.3.345.11）TheHole + Map 状态破坏：小窗口 OOB 读 wasm RWX 并改写 ArrayBuffer/DataView 执行 shellcode](binary-pwn-browser-j2v8-thehole-map-corruption-wasm-rwx.md) | verified | medium | 2026-11-06 |
| [JS 引擎 nvars uint16 回绕：bytecode slot 越界写伪造 JSClass.convert 执行 shellcode](binary-pwn-browser-nvars-uint16-wrap-bytecode-slot-oob-fake-class-convert.md) | verified | high | 2026-11-06 |
| [V8 CVE-2024-12695：Object.assign 缺 properties 类型检查 + FinalizationRegistry 缺 CHECK，SimpleNumberDictionary 头越界后借 WeakCell 链表写构造 cage AAR/AAW 与 wasm execve](binary-pwn-browser-v8-cve-2024-12695-object-assign-finalization-registry-dictionary-oob-wasm-rce.md) | verified | high | 2026-11-06 |
| [V8 TurboFan JS→Wasm 延续帧签名漏比较导致类型混淆](binary-pwn-browser-v8-wasm-frame-state-type-confusion.md) | verified | high | 2026-11-04 |
| [V8 TurboFan ReduceInt32Add 注入 2+2=>5 错误常量折叠 + simplified-lowering 边界检查恒假：JS 数组短距越界泄露 map/properties](binary-pwn-browser-v8-reduceint32add-2plus2eq5-typer-hardening-oob.md) | verified | high | 2026-11-08 |
| [V8 劫持 Wasm LazyCompile：首次调用前篡改 WasmTrustedInstanceData.jump_table_start，使编译完成后跳入错位 shellcode](binary-pwn-browser-v8-wasm-lazycompile-jump-table-start-control-flow-hijack.md) | verified | high | 2026-11-07 |
| [V8 新版 elements map 校验下：只改 JSArray 的 length 与 elements.length 撑大越界，绕开 CHECK 得到稳定 OOB 对象数组与 addrof/fakeobj](binary-pwn-browser-v8-oob-length-overwrite-bypass-elements-map-check-addrof-fakeobj.md) | verified | high | 2026-11-08 |
| [V8 新版 elements map 校验下：新 fake_array 越界改写 JSTypedArray 的 base/external_pointer，控制 data_ptr 实现 AAR/AAW](binary-pwn-browser-v8-fake-array-jstypedarray-dataptr-aar-aaw.md) | verified | high | 2026-11-07 |
| [V8 沙箱内篡改 BytecodeArray 利用 Ignition Ldar/Star 寄存器索引无边界检查实现栈读写与 ROP 沙箱逃逸](binary-pwn-browser-v8-sandbox-bytecode-ldar-star-stack-rop-escape.md) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
