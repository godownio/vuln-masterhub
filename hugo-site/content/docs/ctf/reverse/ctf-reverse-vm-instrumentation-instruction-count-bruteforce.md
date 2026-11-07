---
id: ctf-reverse-vm-instrumentation-instruction-count-bruteforce
title: VM 单字节校验的插桩侧信道爆破：Frida hook opcode 分发计数 / Pintools 指令计数，逐位选执行路径最长的字符
type: scenario
domain: ctf
path: ctf/reverse
technique: vm-instrumentation-instruction-count-bruteforce
tags:
- ctf
- reverse
- vm
- frida
- pintools
- side-channel
- brute-force
- instrumentation
- windows
- linux
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V181
  verified_at: '2026-11-06T17:43:26+08:00'
  notes: 已对照原文核对：Frida hook 0x197F/0x19A2+exit 0x274A、Pintools inscount0 取指令数最大者、逐位拼接流程与原文一致；102864→102988 计数与最终 flag{m4z3d_vm_jump5_42} 见原文截图。未复跑，hook/exit 地址需按目标重定位。
url: /docs/ctf/reverse/ctf-reverse-vm-instrumentation-instruction-count-bruteforce/
draft: false
kb_aliases:
- Frida 爆破 VM
- Pintools 指令计数爆破
- VM 侧信道爆破
- opcode 分发计数
- 单字节加密 VM
- inscount0
- hyperjump
- ezVM
---

## 一句话结论

VM 题若逐字节校验输入、遇到错误字节立即退出，则“正确前缀”会让 VM 多执行若干条指令：用 Frida hook opcode 分发循环计数（或 Pintools `inscount0` 统计执行指令数），对每个候选字符比较计数，保留执行路径最长/指令数最多的字符，逐位拼接即可在不还原完整算法的前提下爆破出 flag。

## 原理

- **逐字节校验的控制流特征**：VM 解释器通常有 `pc` 与一个分发循环；每条 opcode 取指、查跳转表、进 handler。校验第 i 个字节时，若字符错误会立即跳到 `fail/exit`，正确则继续执行后续字节。于是“已输入的前缀是否正确”会体现在 VM 执行的总指令数/分发次数上：正确前缀执行更多指令。
- **Frida 计数**：在 opcode 分发循环入口 `Interceptor.attach`，每次命中 `number += 1`；在失败/退出路径（`retn` 前）attach，`send(number)` 把计数发给 Python 驱动，然后调用目标自身的 `exit` 函数（`NativeFunction`）立即结束进程，避免等待 sleep/交互，提高爆破速度。
- **Pintools 计数**：Pin 的 `inscount0.so` 统计整个进程执行的指令数；用 `pin -t inscount0.so -- target` 对每个候选 payload 跑一次，解析 stdout/`inscount.out` 中的指令数。Pin 在用户态插桩、粒度到指令，计数比 Frida 更稳定、噪声更小，但每次都要重新启动进程，速度较慢。
- **逐位搜索**：维护已知正确前缀 `flag`；对当前位置枚举字符集，构造 `prefix + candidate + padding`，取计数最大者追加到前缀，进入下一位。正确字符使 VM 走得更远，计数呈阶梯上升（文章示例从 102864 到 102988）。
- **为什么不用完整还原**：只需一个可观测的侧信道和“错误即退出”的控制流，不需要理解每条 opcode 的语义；比手写 VM 解释器/Z3 建模更快，适合 opcode 多、分支复杂的题。
- **边界**：若程序先校验全部字节再统一失败、使用哈希/常量时间比较、或存在多条等价路径，计数可能不单调；此时需要结合已知正确前缀、换 hook 点（更靠后的比较分支）、或改用符号执行/约束求解。Frida hook 地址与 exit 地址依赖目标 build，必须按二进制重定位。

## 触发条件

- VM/校验程序逐字节比较输入，遇错立即 `exit`/返回失败；没有常量时间比较或整体哈希。
- 能在目标进程上 attach Frida（Windows/Linux/Android）或运行 Pintools；能定位 opcode 分发循环与失败/退出地址。
- 输入通过 stdin/argv/文件传入，脚本可重复启动或复用进程。
- 已知 flag 长度/字符集/前缀（如 `flag{`），或可逐位推断。

## 利用步骤

1. 逆向后确认校验是逐字节的：找到分发循环、比较分支、fail/exit 路径；记录分发入口与退出点地址。
2. Frida 方案：
   - 编写 JS：hook 分发入口累加计数；hook 退出点 `send(number)` 并调用目标 `exit`；
   - Python 驱动：对每个候选字符启动目标、`frida.attach`、加载脚本、写入 payload、读取计数；
   - 取最大计数对应的字符，追加到已知前缀，重复到长度结束。
3. Pintools 方案：
   - 准备 `inscount0.so` 与 `pin`；
   - 对每个候选 payload 运行 `pin -t inscount0.so -- target`，解析指令数；
   - 同样取最大值；Pin 输出可能写到 stdout 或 `inscount.out`，需兼容解析。
4. 对最终 flag 用原始程序验证；若某位计数并列，增加后续字符上下文/换 hook 点重测。
5. 失败路径优化：在退出 hook 里直接调 `exit(0)`，避免目标进入 sleep/等待，显著加快爆破。

## PoC

Frida hook（地址为示例，需按目标重定位）：

```javascript
var number = 22;
function main() {
  var base = Module.findBaseAddress("vm.exe");
  if (base) {
    // opcode 分发循环入口：每次分发 +1
    Interceptor.attach(base.add(0x197F), {
      onEnter: function(args) { number += 1; }
    });
    // 失败/退出点：发送计数并立即 exit，避免等待
    Interceptor.attach(base.add(0x19A2), {
      onEnter: function(args) {
        send(number);
        var f = new NativeFunction(base.add(0x274A), 'void', ['int']);
        f(0);
      }
    });
  }
}
setImmediate(main);
```

Python 逐位驱动（骨架）：

```python
import subprocess, frida

number = 0
def on_message(message, data):
    global number
    if message['type'] == 'send':
        number = message['payload']

jscode = open('hook.js', 'rb').read().decode()
flag = "flag{"
charset = "abcdefghijklmnopqrstuvwxyz0123456789_@{}"

for index in range(len(flag), 44):
    best, best_count = None, -1
    for ch in charset:
        p = subprocess.Popen("ezVM.exe", stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        session = frida.attach("ezVM.exe")
        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()
        p.stdin.write(((flag + ch).ljust(43, "A") + "}").encode())
        p.communicate()
        if number > best_count:
            best, best_count = ch, number
        session.detach(); p.terminate()
    flag += best
    print(flag)
```

Pintools 逐位驱动（骨架）：

```python
import subprocess, re, string
PIN = ['/root/pin/pin', '-t', './pintools/inscount0.so', '--', './hyperjump']
CHARSET = string.ascii_lowercase + string.digits + "_@{}"
FLAG_LEN = 24

def get_inscount(payload):
    p = subprocess.run(PIN, input=payload + '\n', capture_output=True, text=True, timeout=5)
    m = re.search(r'(\d+)\s+instructions', p.stdout + p.stderr)
    return int(m.group(1)) if m else 0

known = list("A" * FLAG_LEN)
for i in range(FLAG_LEN):
    best, best_count = None, -1
    for ch in CHARSET:
        cand = known[:]; cand[i] = ch
        cnt = get_inscount(''.join(cand))
        if cnt > best_count:
            best, best_count = ch, cnt
    known[i] = best
    print(''.join(known))
# flag{m4z3d_vm_jump5_42}
```

## 变体与关联

- **符号执行/约束求解**：若计数不单调或校验不是逐字节，可在分发器/比较分支上做符号执行，把输入建模为 BitVec 求满足条件的解；见 [[ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution]]、[[ctf-reverse-custom-stack-vm-bytecode-constraint-recovery]]。
- **Ponce/IDA 插件**：在调试器里把输入内存标记为 symbolic，在比较分支用 SMT 求解，属于同一类“动态符号执行”变体；文章 HSCCTF 示例即用 Ponce 的 Symbolize memory + SMT Solver。
- **换 hook 点**：不 hook 分发循环而 hook 每次比较后的分支/putchar，可减少噪声；若 VM 使用多线程/异步，需绑定线程或 hook 线程入口。
- **反插桩**：目标可能检测 Frida/Pin（端口、线程名、模块、时间差）；需先绕过反调试，或改用静态还原/Z3。
- 边界：计数爆破依赖“错误即退出 + 正确前缀执行更长”；对整体哈希/常量时间校验无效。

## 检测与防御

- 对题目设计：避免逐字节提前返回；可先校验全部字节再统一失败，或使用常量时间比较/HMAC；加入随机延迟、反调试/反插桩检测，增加计数噪声。
- 对真实软件：VM/字节码混淆不是安全边界；侧信道（指令数、分支数、时间）可泄露校验进度；应使用标准密码学与常量时间实现。
- 检测：Frida/Pin 注入痕迹、进程被 attach、异常高的启动次数与相似 payload、指令数随输入变化的模式；EDR 可监控 `ptrace`/调试端口/注入模块。
