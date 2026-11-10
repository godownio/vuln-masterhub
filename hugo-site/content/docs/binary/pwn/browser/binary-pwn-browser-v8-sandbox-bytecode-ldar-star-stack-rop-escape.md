---
id: binary-pwn-browser-v8-sandbox-bytecode-ldar-star-stack-rop-escape
title: V8 沙箱内篡改 BytecodeArray 利用 Ignition Ldar/Star 寄存器索引无边界检查实现栈读写与 ROP 沙箱逃逸
type: scenario
domain: binary
path: binary/pwn/browser
technique: bytecode-corruption-interpreter-register-oob
tags:
- v8
- sandbox-escape
- ignition
- bytecode
- rop
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-27
  verified_at: '2026-11-08T14:58:14+08:00'
  notes: 已对照原文核对：Ldar/Star 无边界检查原理、BytecodeArray 篡改链、d8 基址拼接泄漏、假栈 ROP execvp 均与原文一致；img/04 显示 id/uname 输出即逃逸成功；patch 条件竞争半链原文自认非预期解未验证，已按规则跳过且卡内如实标注。未验证点：未本地复跑 exp；卡未带 sources 字段（原文含官方 solution 链接）。
url: /docs/binary/pwn/browser/binary-pwn-browser-v8-sandbox-bytecode-ldar-star-stack-rop-escape/
draft: false
kb_aliases:
- V8 sandbox escape via bytecode array corruption
- Ignition Ldar/Star register index OOB
---

# 一句话结论

在启用 `v8_enable_sandbox` 的 V8/d8 中，攻击者拿到沙箱内（4GB 指针压缩笼内）任意读写后，可直接改写函数的 BytecodeArray 字节：Ignition 解释器的 Ldar/Star handler 用带符号字节作为寄存器索引、且不做边界检查，`mov rdx, rbp; mov rbx, [rdx+rbx*8]` 直接以 rbp 为基址索引栈，从而获得栈上 8 字节任意写与低 32 位泄漏原语，进一步栈迁移劫持控制流并 ROP 调用 execvp("/bin/sh")，完全逃逸 V8 沙箱拿到系统 shell。

# 原理

V8 沙箱把 JS 对象堆限制在指针压缩笼内，沙箱内的任意读写传统上被认为不足以逃逸（外部指针表、code pointer table 等隔离了沙箱内指针）。但 Ignition 解释器执行时，字节码操作数即寄存器索引：Ldar handler 的汇编为 `movsx rbx, byte ptr [r12+r9+1]; mov rdx, rbp; mov rbx, qword ptr [rdx+rbx*8]`，其中 r12 是 BytecodeArray 基址、rbp 是解释器栈帧基址。索引是带符号单字节（-128~127）且完全没有与 frame size 比对，因此：

- Ldar 读 `[rbp + idx*8]`：idx 为负/正值可读栈上任意 8 字节，结果作为 JS 值返回时因指针压缩只保留低 32 位（smi 再右移 1 位还原）。
- Star 写 `[rbp + idx*8] = rax`：rax 是上一条指令的返回值，可向栈上写入完整 8 字节（例如 d8 内 Builtins 地址，用于泄漏高位拼接或写栈）。

攻击者只要能在沙箱内写 BytecodeArray 的字节数组内容，就能给任意函数"重编程"。本场景中沙箱内读写由编译选项 `v8_expose_memory_corruption_api` 暴露的 `Sandbox.MemoryView`（DataView 包装沙箱基址+偏移）提供——这模拟的是"已有一个沙箱内漏洞"的前提；真实攻击中任何沙箱内 OOB/UAF 读写都可替代。

逃逸路径：栈上写可控制保存的 rbp（多次 leave 实现栈迁移）；d8 基址泄漏靠两点——栈上残留的 d8 .text 地址给低 32 位（ASLR 下低 4 位页内偏移固定、跨次运行低位变化极小），高 32 位从堆 chunk 头部（仍有读权限的元数据区，如 0x40014/0x4001c 偏移处的 vtable/分配器指针）读取后拼接，减去固定文件偏移得到 d8 base。之后在沙箱内堆上布置假栈（JS Array 元素区）写入 ROP 链（pop rdi/rsi/rdx + execvp@plt + "/bin/sh"），再把目标函数的 BytecodeArray 整体伪造/重定向到自建字节码（修改 JSFunction→SharedFunctionInfo→BytecodeArray 指针链），执行 Ldar/Star 序列完成栈迁移与 ROP，最终 execvp 拿 shell。

# 触发条件

- 目标为启用 `v8_enable_sandbox`（+ 可选 `v8_code_pointer_sandboxing`）的 V8/d8，JIT/Maglev/Turbofan/WebAssembly 可全部关闭（v8_jitless 下 Ignition 仍工作，链路不受影响）。
- 攻击者已具备沙箱内（指针压缩笼内）任意读写原语：本场景由 `v8_expose_memory_corruption_api` 的 Sandbox API 提供，真实场景可为任意沙箱内内存破坏漏洞。
- 解释器使用 Ignition 且 Ldar/Star handler 未对寄存器索引做边界检查（对应 V8 11.x/12.x 时期的实现）。

# 利用步骤

1. 用 `Sandbox.getAddressOf` 拿到目标函数对象地址，沿 JSFunction→SharedFunctionInfo(+0xc)→BytecodeArray(+0x4) 链定位字节码数据；用 `new Sandbox.MemoryView(0, 0x100000000)` + DataView `setUint8` 逐字节改写。
2. 从堆基址附近固定偏移（0x40014/0x4001c/0x40020）读指针得到沙箱基址高/低 32 位与 d8 基址高 32 位。
3. 把函数字节码开头改写为 `Ldar a1(+0x10 相对偏移 0xb); Star idx(0x18); Return(0xaa)` 之类序列：Ldar 读栈上含 d8 .text 地址的槽位（低 32 位，smi*2 还原），Star 可向 [rbp+idx*8] 写 8 字节，实现栈泄漏与受控写。
4. 拼接高低位得到 d8 base；从 d8 取 gadget：pop rdi/rsi/rdx、ret、execvp@plt。
5. 在沙箱内布置假栈：JS Array 的 elements 区写 ROP 链与 "/bin/sh" 字符串；伪造 BytecodeArray 结构（复制合法头部字段后自定义指令流），把原函数的 BytecodeArray 指针/长度字段指向伪造体，并把栈上返回地址槽改写为 ret gadget。
6. 调用该函数，解释器按伪造字节码执行多次 leave/栈迁移，切到假栈跑 ROP，execvp("/bin/sh") 得到宿主 shell。

# PoC

见原文 exp（Google CTF 2023 v8box 官方解法复现）：核心片段——

```javascript
let memory = new DataView(new Sandbox.MemoryView(0, 0x100000000));
// 定位并改写字节码
var shared_info = getField(addressOf(h), 0xc);
var bytecode_addr = getField(shared_info, 0x4) & (~tag);
memory.setUint8(bytecode_addr + 0x20, 0xb);  // Ldar
memory.setUint8(bytecode_addr + 0x21, 0x10); // 寄存器索引
memory.setUint8(bytecode_addr + 0x22, 0xaa); // Return
var leak = h() * 2;  // 低32位泄漏栈上 d8 地址
// 后续：拼 d8 base、布置假栈 ROP 链、execvp("/bin/sh")
```

实测输出 d8_base/execvp_plt 等地址后成功执行 `id`/`uname`，获得宿主 shell。

# 变体与关联

- 同类思路：直接篡改 JIT/builtin 相关结构的场景（fake JSFunction、WASM jump table 劫持）；code pointer sandboxing 开启后函数指针不可直接改写，但解释器数据流（BytecodeArray 内容）仍可篡改——数据与代码的边界在解释器模型中天然模糊。
- patch 中 RwMemoryWriteScope 用 thread_local nesting_level_ 保护 chunk 头存在多线程条件竞争（SetWritable/SetReadOnly 跨线程交错），文中提及但非预期解法，未验证。
- 与"bytecode slot 越界"类卡（如 nvars uint16 回绕）同属解释器寄存器/槽位边界缺失这一 sink 家族，但本场景入口是沙箱内任意写而非引擎内计数器回绕。

# 检测与防御

- 在 Ldar/Star（及所有以操作数为寄存器索引的字节码）handler 中对索引与 frame size 做边界校验，或改用无符号/带掩码索引。
- 对 BytecodeArray 所在内存做完整性保护：将其移入可信/只读空间（V8 后续的 trusted space 方向），使沙箱内写原语无法触达字节码数据。
- 生产构建绝不开启 `v8_expose_memory_corruption_api`；fuzzing/CTF 镜像与生产二进制严格分离。
- 检测：监控对 BytecodeArray 内容的异常写入（堆完整性校验、CFI/字节码校验和）；d8 调试构建可开启 verify_heap。
