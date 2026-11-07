---
id: tools-ida-python-conditional-breakpoint-register
title: IDA 条件断点用 IDAPython 判断寄存器：call rand 后 rax==16949 才断下
type: scenario
domain: tools
path: tools/ida
technique: ida-python-conditional-breakpoint-register
aliases:
- IDA Python 条件断点
- 寄存器条件断点
- bp() 条件断点
- idc.get_reg_value
- rand 返回值断点
tags:
- ida
- idapython
- debugging
- conditional-breakpoint
- reverse
- register
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T13:34:16+08:00'
  notes: 已对照原文及图01-06核对：bp() 用 idc.get_reg_value('rax')==16949，断点设在 call rand 后的 mov 指令，RAX=0x4235 命中；操作路径 Breakpoint settings→Condition→Edit script→Python 与截图一致；未在 IDA 复跑
---

## 一句话结论

在 IDA 调试时，把断点条件设为自定义 Python 函数 `bp()`，函数内用 `idc.get_reg_value('rax')` 读取当前寄存器并返回布尔值，即可让程序只在 `call rand` 返回值为 `16949`（`0x4235`）时断下，其他情况自动继续。

## 原理

- **断点条件是每次命中断点时求值的表达式**：IDA 允许在 Breakpoint settings 的 Condition 中选择脚本语言并执行代码；返回非零/True 时断下，False 时继续运行。
- **寄存器读取**：`idc.get_reg_value('rax')` 读取当前线程的寄存器值；函数返回时 x86-64 的返回值在 `rax`（32 位在 `eax`，ARM64 在 `x0`）。
- **断点位置很关键**：必须把断点设在 `call rand` 之后（如 `mov ecx, [rbp+...]` 处），此时返回值已写入 `rax`；设在 `call` 之前读到的是旧值。
- **条件函数在调试器上下文执行**：Python 控制台定义的 `bp()` 在断点命中时由 IDA 调用，可使用 `idc`/`idaapi` 读取寄存器、内存、线程信息，也可写日志；因此条件断点不仅能筛选，还能做轻量 hook（打印参数、计数、修改内存等）。
- **十六进制与十进制**：`0x4235` 等于 `16949`；脚本里用十进制比较时注意 IDA 返回值类型为 int。

## 触发条件

- 使用 IDA 调试器（本地或远程）并已附加/启动目标进程，目标架构支持 `idc.get_reg_value`。
- 目标有明确的返回点（如 `call rand`）和可预测的寄存器（返回值在 `rax`/`eax`/`x0`）。
- 断点设在返回指令之后；条件语言选择 Python（非 IDC）。
- 目标不是强反调试/代码自校验环境，否则条件断点可能被检测或触发异常。

## 利用步骤

1. 在 IDA 的 Python 控制台定义条件函数：
   ```python
   def bp():
       rax = idc.get_reg_value('rax')
       return rax == 16949
   ```
2. 在 `call rand` 的下一条指令处设置普通断点（F2）。
3. 右键断点 → `Edit breakpoint...` → `Condition` 行右侧 `...`。
4. 在 `Edit script` 对话框输入 `bp()`，`Scripting language` 选择 `Python`，`Compile`/`OK`。
5. 运行程序（F9）；每次执行到断点都会调用 `bp()`，只有 `rax == 0x4235` 时停下，其余自动继续。
6. 断下后检查寄存器窗口/调用栈，或让 `bp()` 同时打印 `idc.get_reg_value` 及内存值做记录。

## PoC

```python
# IDA Python 控制台
def bp():
    rax = idc.get_reg_value('rax')
    return rax == 16949
```

```text
断点位置：.text:...780  mov ecx, [rbp+110h+var_10C]   ; call rand 之后
Condition: bp()
Scripting language: Python
```

```python
# 变体：同时记录命中值并只在目标值时断下
def bp():
    rax = idc.get_reg_value('rax')
    if rax == 0x4235:
        print("[hit] rand() = 0x%x" % rax)
        return True
    return False
```

原文在样本中验证 `RAX=0x4235` 时断下；本卡未在 IDA 中复跑。

## 变体与关联

- **变体：其它寄存器/架构**：x86 用 `eax`，ARM64 用 `x0`/`w0`；`idc.get_reg_value` 支持常见通用寄存器，名称以 IDA 寄存器窗口为准。
- **变体：内存条件**：`idc.get_wide_dword(addr) == value`、`idc.get_bytes(addr, n)` 比较缓冲区内容，可做“某个全局变量/输入缓冲区满足条件才断”。
- **变体：有副作用的 hook**：条件函数里打印参数、调用 `idc.set_reg_value` 改寄存器、写文件统计；注意每次命中都会执行，性能开销随命中次数增长。
- **关联**：[[tools-ida-fork-child-loop-patch-attach]]（子进程调试）、[[tools-ida-trace-instruction-basicblock-function-export]]（Trace 记录执行流）。
- **边界**：断点位置错误、返回值被后续指令覆盖、条件脚本异常都会导致永不断下或误断；强反调试程序可能检测软件断点，必要时改用硬件断点。

## 检测与防御

- 这是调试器使用技巧，不是攻击链；对恶意样本分析而言，可用于定位随机数/校验值/协议字段。
- 注意事项：条件脚本尽量短小；大量命中时 Python 条件会显著拖慢调试；修改寄存器/内存前备份；远程调试时 `idc.get_reg_value` 读取的是被调试进程上下文。
- 对抗视角：样本若检测 INT3/硬件断点、校验代码段，条件断点可能失效；可改用 Trace、模拟执行或 Frida hook 替代。
