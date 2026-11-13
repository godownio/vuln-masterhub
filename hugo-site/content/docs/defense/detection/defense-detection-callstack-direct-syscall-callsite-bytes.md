---
id: defense-detection-callstack-direct-syscall-callsite-bytes
title: 调用堆栈检测直接系统调用：call_stack_summary 不以 ntdll 结尾 + callsite_leading_bytes 匹配 mov r10,rcx/mov eax,ssn/syscall
type: scenario
domain: defense
path: defense/detection
technique: callstack-direct-syscall-callsite-bytes
tags:
- defense
- detection
- call-stack
- elastic
- eql
- edr
- windows
- direct-syscall
- syscall
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V510
  verified_at: '2026-11-11T05:02:07+08:00'
  notes: 已对照原文与 img14 核对：四种 callsite_leading_bytes 模式（含 *4c8bd1b8??????000f05、*4989cab8??????000f05、*4c8bd10f05、*4989ca0f05）与原文逐字一致；截图命中 Unbacked|kernel32.dll|ntdll.dll、call_stack_contains_unbacked=true、Unbacked 帧 protection RWX。原卡把截图字节描述为 ...890f05，实际红框为 4989ca0f05（49 89 CA; 0F 05），已修正。dedup 候选为攻方直调/自定义栈卡，非同链。原文未给组件版本，未设 affected_versions；无 sources/source_url。
url: /docs/defense/detection/defense-detection-callstack-direct-syscall-callsite-bytes/
draft: false
kb_aliases:
- 直接系统调用检测
- direct syscall detection
- callsite_leading_bytes
- 4c8bd1b80f05
- syscall stub 检测
- Elastic Defend 直调检测
---

## 一句话结论

直接系统调用绕过用户态 API 挂钩，调用栈通常不以 `ntdll.dll` 帧收尾，且最后一段未支持（unbacked）内存的起始字节包含手写 syscall stub 特征（`mov r10,rcx; mov eax,ssn; syscall`，机器码 `4C 8B D1 B8 ?? ?? ?? ?? 0F 05` 或其变体）。用 EQL 同时匹配“栈不以 ntdll 结尾”与 `callsite_leading_bytes` 正则，可在进程创建等事件上高置信度发现直调行为。

## 原理

- **正常路径**：Windows API 最终经 `ntdll.dll` 的 `Nt*` 存根进入内核，`syscall` 指令位于 ntdll 内；安全产品通常在 ntdll 导出或更高层挂用户态钩子。
- **直接系统调用**：攻击者在自己的内存里实现存根，按目标系统版本填入系统调用号（SSN），直接执行 `syscall`，不经过 ntdll，因此绕过用户态 API 挂钩。典型指令序列是 `mov r10, rcx`（`4C 8B D1`）、`mov eax, ssn`（`B8 ?? ?? ?? ??`）、`syscall`（`0F 05`）；也有 `mov r10, rcx` 的等价写法 `mov r10, rcx`/`xchg` 变体（`49 89 CA` 等）。
- **调用栈特征**：直调时调用链的最后一段来自攻击者的未支持内存（unbacked），且该内存页常为 RWX；栈中不会出现 ntdll 的 `Nt*` 帧。EDR 的 `process.parent.thread.Ext.call_stack` 会记录每一帧的 `symbol_info` 与 `callsite_leading_bytes`（帧所在位置的起始指令字节），可直接做字节级匹配。
- **为什么有效**：系统调用号与 stub 字节布局是直调的实现必需；即使攻击者换用间接系统调用（jmp 到 ntdll 的 syscall 指令），字节模式或栈形态也会变化，可另建规则。
- **边界**：调用栈欺骗（伪造 ntdll 帧）或 SSN 动态解析会降低命中率；短格式 `4C 8B D1 0F 05`/`49 89 CA 0F 05` 也要覆盖，避免只匹配完整 stub。

## 触发条件

- EDR 采集进程事件及父线程调用栈的符号与 `callsite_leading_bytes` 字段。
- 目标为 Windows；攻击者使用直接系统调用（或含直调 stub 的 shellcode/loader）执行敏感操作（如进程创建）。
- 规则用于检测/狩猎。

## 利用步骤（检测步骤）

1. 确认 EDR 的调用栈事件包含 `callsite_leading_bytes`（十六进制指令字节）与 `call_stack_summary`。
2. 部署 EQL：进程启动事件中，父线程栈 `call_stack_summary` 不以 `ntdll.dll` 开头/结尾，且任一帧的 `callsite_leading_bytes` 匹配四种 stub 模式。
3. 命中后检查最后一段内存的 `protection`（RWX 可疑）、符号是否为空/Unbacked、所属模块是否未签名。
4. 结合父进程、命令行、后续行为定性；若攻击者改用间接系统调用，检查是否出现 `jmp` 到 ntdll 的短跳转与异常栈。

## PoC

```eql
process where event.action : "start" and

// 调用栈不以 ntdll.dll 收尾
not process.parent.thread.Ext.call_stack_summary : "ntdll.dll*" and

/* 栈最后一段包含手写 syscall stub：
   mov r10,rcx; mov eax,ssn; syscall 及其变体 */
_arraysearch(process.parent.thread.Ext.call_stack, $entry,
 ($entry.callsite_leading_bytes : ("*4c8bd1b8??????000f05",
                                    "*4989cab8??????000f05",
                                    "*4c8bd10f05",
                                    "*4989ca0f05")))
```

原文截图中命中记录的 `call_stack_summary` 为 `Unbacked|kernel32.dll|ntdll.dll`，`call_stack_contains_unbacked: true`，未支持帧 `protection: RWX`，`callsite_leading_bytes` 含 `4989ca0f05`（`49 89 CA; 0F 05`）形式的 syscall 结尾。

## 变体与关联

- **间接系统调用**：自写 stub `jmp` 到 ntdll 的 `syscall` 指令，栈可能仍以 ntdll 结尾，但 callsite 字节是短跳转，需要补充规则。
- **WOW64 直调**：32 位进程用 `FS:[0xC0]` 调 `wow64cpu!KiFastSystemCall`，检测点不同，见 `pentest-c2-wow64-fs-c0-kifastsystemcall-direct-syscall`。
- **关联卡**：`pentest-c2-indirect-syscall-jmp-ntdll-syscall-stub`、`pentest-c2-custom-call-stack-tpallocwork-threadpool-syscall`（栈欺骗视角）。
- **绕过检测**：调用栈伪造可让栈看起来以 ntdll 结尾；此时依赖 callsite 字节、unbacked 内存与行为关联。

## 检测与防御

- **检测**：上述 EQL；补充对 RWX unbacked 内存、线程起始地址不在模块内、`syscall` 指令出现在非 ntdll 页的扫描。
- **降噪**：JIT/浏览器等也会产生可执行内存，需按进程、签名、调用栈与保护属性组合过滤。
- **加固**：启用 HVCI/CFG/CIG 与内核态遥测；限制未签名代码执行；使用支持 ETW-TI 与调用栈完整性的 EDR。
- **响应**：提取命中进程内存，定位直调 stub 与 SSN 解析逻辑，关联其后续网络与文件行为。
