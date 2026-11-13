---
id: code-analysis-dynamic-fuzzing-qemu-fullsystem-lua-instrument-forkserver
title: 基于 QEMU 全系统模拟的通用化 fuzzing：Lua 插桩统计覆盖率、guest 内选点 fork、PGD 区分进程、Lua 覆盖内存注入输入
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: qemu-fullsystem-lua-instrument-forkserver-fuzzing
tags:
- fuzzing
- qemu
- full-system-emulation
- lua
- luajit
- forkserver
- coverage
- firmware
- iot
- afl
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V624
  verified_at: '2026-11-12T22:22:33+08:00'
  notes: 已逐张阅读12636全部26张PPT核对：AFL用户态qemu mode局限、TriforceAFL天然snapshot与guest agent/hypercall缺点、LuaQEMU断点/寄存器内存接口、TB翻译前gen afl_maybe_log更新bitmap、按PGD(x86 cr3/ARM ttbr0/MIPS读guest内存)区分进程、forkserver时机(网络accept记fd/首次recv返回fork、CGI main fork+exit syscall退出)、Lua覆盖内存注入、page fault启发式判crash、FirmAFL/Cmp插桩/QASAN展望，均与截图一致；Lua PoC骨架与截图lua脚本吻合。卡片原子、为全系统自插桩框架场景，与AFL -Q用户态qemu(0.850)/AFL LLVM forkserver(0.856)/固件user-mode仿真等非同链，dup-scan不涉及。无受影响版本不设versions。未验证点：框架未开源、无完整可运行PoC，卡片已注明为骨架示意；PPT无文字稿，细节均来自截图。
url: /docs/code-analysis/dynamic/fuzzing/code-analysis-dynamic-fuzzing-qemu-fullsystem-lua-instrument-forkserver/
draft: false
kb_aliases:
- QEMU 全系统 fuzzing
- LuaQEMU 插桩
- TriforceAFL 替代
- 固件 fuzzing 框架
- 无源码全系统模糊测试
- guest 内 forkserver
---

## 一句话结论

AFL 用户态 qemu mode 只能 fuzz 单个闭源用户态程序，固件/内核这类必须全系统模拟的目标无法直接使用；可在 qemu-system 上用 LuaQEMU 的 Lua 接口做插桩——在 TB 翻译前插入 `afl_maybe_log` 统计覆盖、按页表基址（x86 cr3 / ARM ttbr0）区分 guest 进程、在业务逻辑前选点 fork 子进程、用 Lua 直接覆盖 guest 内存注入输入，并以缺页/page fault 启发式判崩溃，从而在不修改 guest 的前提下把 AFL 的覆盖率引导 fuzzing 通用化到 IoT 固件与网络边界设备。

## 原理

- **为什么需要全系统模拟**：固件与内核场景依赖启动流程、驱动、多进程与网络协议栈，用户态 qemu mode 只模拟单一进程无法进入业务逻辑；全系统模拟能复现完整环境，但代价是速度与插桩复杂度。
- **天然 snapshot**：qemu-system 自身保存 guest 的全部 CPU/内存/设备状态；fork 一个 QEMU 进程即复制整套 guest 状态。TriforceAFL 即利用这一点做快照式 fuzz，但需要 guest 内 agent 与 hypercall 配合（要在 guest 里放代码），对闭源固件不友好。
- **LuaQEMU 免改 guest**：基于 luajit 给 QEMU 加 Lua 接口，可以设断点与回调函数、读写 guest 寄存器与内存；攻击面（harness 逻辑）完全放在 QEMU 侧的 Lua 脚本里，guest 二进制与固件保持原样。
- **覆盖率统计**：把 AFL 的 `afl_maybe_log` 插桩点放在 QEMU TCG 的 TB 生成阶段（`tb_gen_code` 前），每个翻译块执行时更新 bitmap；BB→TB→afl_maybe_log→Bitmap 的映射保证 AFL 端能收到 edge 覆盖。
- **多进程区分（PGD）**：全系统里同时存在 init 等多个进程，同一个虚拟地址在不同进程是不同代码；必须按页表基址（x86 `cr3`、ARM `ttbr0`、MIPS 从 guest 内存读取）给不同地址空间的 TB 分配互不重叠的 bitmap 区段，否则覆盖率会互相污染、AFL 误判新边。
- **forkserver 插入时机**：AFL 的 forkserver/bitmap 机制要求每次执行从同一状态开始并很快走到输入处理；全系统里 fork 点要选在"已经完成初始化、马上要处理输入"的位置——网络服务在 accept 记录 fd、第一次 recv 返回时 fork；CGI 类在 main 入口 fork、监控 exit syscall 作为退出点。原则是"能输入数据"且"尽量接近数据处理逻辑"。
- **输入注入**：用 Lua API 直接写 guest 内存——网络程序覆盖 recv 缓冲区；CGI 的 GET 请求写环境变量所在栈内存，POST 类似网络程序写缓冲区。这样无需 guest 内的 fuzzing harness。
- **崩溃检测**：全系统下 guest 进程崩溃不直接体现为宿主信号，需基于 page fault 的启发式（guest 触发缺页/SIGSEGV 时由 QEMU 侧判定为 crash 候选）；命令注入、目录穿越、逻辑漏洞不属于崩溃类，需要额外断言或污点分析，框架本身只能覆盖内存破坏类问题。

## 触发条件

- 目标为无源码的闭源固件/网络设备/内核组件，必须全系统模拟才能进入业务逻辑（Linux-based 固件或 RTOS）。
- 能搭建 qemu-system 环境并定位业务输入点（网络服务、CGI、协议解析）。
- 有 LuaQEMU 或等价的可编程插桩 QEMU（TCG 层可插入回调）。
- 具备 AFL 端与 guest 状态快照/fork 的集成能力；接受全系统模拟带来的吞吐下降（比用户态插桩慢一个量级以上）。

## 利用步骤

1. 用 qemu-system 启动固件/镜像，确认网络或 CLI 能正常交互，定位业务逻辑入口（listen/accept/recv、CGI main、协议解析函数）。
2. 在 QEMU 侧加载 Lua 脚本：设置代码区间（afl_set_range）与基址，插桩 TB 翻译（`afl_maybe_log`），初始化 bitmap 与 PGD 进程区段。
3. 在业务入口插断点：网络服务在第一次 recv 前记录 fd，首次 recv 返回时进入 forkserver；CGI 在 main 处 fork，注册 exit syscall 断点作为一次执行结束。
4. 每次 fuzz 迭代由 Lua 把 AFL 传来的测试数据写入 guest 对应内存（recv buffer / 环境变量），恢复快照后继续执行。
5. 在 page fault 处理路径收集崩溃现场（寄存器、PC、内存），按信号/PC 去重后交给 AFL 落盘。
6. 用 AFL 的 forkserver protocol 与 bitmap 对接，跑覆盖率引导；按 crash 样本 GDB/asan（guest 内）复现定位。

## PoC

无完整可运行 PoC（原始材料为演讲框架，未开源完整代码）。Lua 侧核心骨架示意：

```lua
-- 覆盖率与进程区段初始化
function afl_init()
  lua_afl_set_range(afl_code_start, afl_code_end)
  lua_afl_set_code_base(afl_code_base)
  lua_breakpoint_insert(start_inst_addr, bp_func_start)
end

-- 进入 forkserver 并挂载结束/危险点断点
function bp_start_fork_server()
  if bp_real_fork == 0 then
    bp_real_fork = 1
    for i, v in ipairs(endpoint_list)  do lua_breakpoint_insert(v, bp_func_end)  end
    for i, v in ipairs(sinkpoint_list) do lua_breakpoint_insert(v, bp_func_sink) end
    lua_afl_disable_interrupt(1)
    lua_afl_enable_fault_monitor(C.FMOSFault)
    lua_afl_forkerserver(1)
  end
  lua_continue()
end
```

输入注入与 PGD 区分为思路级操作（`lua_memory_write(addr, data, len)`；按 cr3/ttbr0 计算 bitmap 偏移），需按实际 QEMU 版本接口实现。

## 变体与关联

- 关联：[[code-analysis-dynamic-fuzzing-afl-stdin-qemu-modes-ui-metrics]]（AFL 用户态 `-Q` qemu mode 的基础用法，本卡是其"全系统 + 自插桩"延伸）、[[code-analysis-dynamic-fuzzing-afl-llvm-runtime-forkserver-persistent-deferred]]（AFL forkserver 机制的用户态形态）。
- 变体：TriforceAFL（guest 内 agent + hypercall，需改 guest）；FirmAFL（结合 qemu usermode 提升速度）；QASAN（全系统下的内存错误检测）；Cmp 指令插桩与定制 mutator 提升覆盖率。
- 边界：非崩溃类漏洞（命令注入、目录穿越、逻辑问题）不会被 page fault 启发式捕获，需要额外检测层；全系统模拟吞吐低，需并行与快照优化。

## 检测与防御

- 这是安全测试/漏洞挖掘手法，本身不针对特定受害者；防御视角的对应面是固件与网络边界设备的漏洞治理：减少闭源不可审计组件、启用 ASLR/栈保护等缓解、对协议解析做长度与状态校验。
- 对设备厂商：在发布前用同类全系统 fuzzing 自测固件；对运维方：网络边界设备定期升级与隔离，避免长期暴露可利用的解析器漏洞。
