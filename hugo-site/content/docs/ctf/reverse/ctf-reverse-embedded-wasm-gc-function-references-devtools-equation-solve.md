---
id: ctf-reverse-embedded-wasm-gc-function-references-devtools-equation-solve
title: 内嵌 wasm 校验逆向：Wasm GC/函数引用类型令 wasm2c 失败，改 Chrome 断点观察运行时异或解密的 g 数组并解 4 元方程组（TetCTF babywasm）
type: scenario
domain: ctf
path: ctf/reverse
technique: wasm-gc-function-references-devtools-equation-solve
tags:
- ctf
- reverse
- wasm
- webassembly
- gc-proposal
- function-references
- devtools
- equation-solving
- z3
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V577
  verified_at: '2026-11-12T11:13:43+08:00'
  notes: 已对照原文与13张图核对：内嵌十进制字节码、wabt1.0.34 wasm2c报unexpected type form (got -0x30)、wabt维护者不支持function-references/gc、DevTools中check签名(ref null type1)与type incompatibility、运行时XOR 19/55/32/36解密假g数组、5组4元方程；卡片PoC实测解出TetCTF{WebAss3mblyMystique}。CTF题无affected_versions。dedup最近候选code-analysis-reverse-wasm-browser-debug-memory-helpers为Go wasm AES通用双路径案例，非同链。未验证点：无。
url: /docs/ctf/reverse/ctf-reverse-embedded-wasm-gc-function-references-devtools-equation-solve/
draft: false
kb_aliases:
- TetCTF babywasm
- WebAssembly 内嵌字节码
- wasm2c unexpected type form
- Wasm GC 逆向
- 函数引用提案逆向
- Chrome wasm 断点调试
- 运行时全局解密
---

## 一句话结论

CTF 题目把 wasm 字节码以十进制数组内嵌在 JS 中，且模块使用 Wasm GC/function-references 提案的类型定义，wabt `wasm2c` 会报 `unexpected type form (got -0x30)` 无法反编译；改用 Chrome DevTools 在导出的 `init`/`array_fill`/`check` 上下断点，观察模块启动时用 XOR 19/55/32/36 对初始全局常量做运行时解密得到的真实 g 数组，即可把校验还原成"每 4 个输入字符一组"的 4 元方程组，爆破或 z3 求解出 flag。

## 原理

- **内嵌字节码的形态**：页面里 `code = [0,97,115,109,1,0,0,0,...]` 是 wasm 魔数 `\0asm` + 版本号的十进制数组，`new Uint8Array(code)` 后交给 `WebAssembly.Module/Instance`；模块导出 `{init, array_fill, check}`。收集这些十进制数用 CyberChef 的 "From Decimal" 或 Python `bytes(code)` 即可还原 `.wasm`。
- **校验流程**：JS 先要求输入满足 `TetCTF{...}`、长度 27；然后 `array_size=20`，循环 `array_fill(array_obj, i, text.charCodeAt(i+7))` 把花括号内的 20 个字符填入 wasm 数组；最后 `check(array_obj)` 返回真假。也就是说 flag 体（含右花括号）共 20 字节参与校验。
- **静态工具的失败点**：wabt 1.0.34 的 `wasm2c` 报 `000000c: error: unexpected type form (got -0x30)`；原因是模块用了 Wasm GC / function-references 提案的类型：`(type $type0 (struct (field $field0 (mut i32))))`、`(type $type1 (array (field (mut (ref null $type0)))))`，函数参数写成 `(ref null $type1)`。当时 wabt 明确不支持 function-references 与 GC 提案，所以 `wasm2c`/`wasm2wat` 这条最方便的路径失效；JEB 能打开并反编译出部分伪代码，但可读性差、基本靠猜。
- **浏览器动调绕过版本限制**：Chrome 的 wasm 引擎支持这些新提案，DevTools → Sources 中可直接查看 wat 并下断点。在 `$check` 断点可看到 `(func $check (param $var0 (ref null $type1)))` 调用 `$3`/`$4` 以及 `$global0..`；由于引用类型参数无法从 JS 直接构造，console 里 `wasm.check()` 会抛 `type incompatibility`，需通过页面输入或临时改页面脚本触发。
- **运行时全局解密（本题的坑）**：data 段初始化的 `$global0..19` 是假值（96,101,20,177,155,...），模块启动函数会逐个 `global.get` → `i32.const k` → `i32.xor` → `global.set`，k 按 19、55、32、36 循环，得到真实 g 数组（115,82,52,149,136,67,...）。只静态看 wat 会拿假密钥，必须在初始化后读取或在断点时观察。
- **方程还原**：`$check` 对比的密文 t 是 20 个常量（38793,584,738,38594,...）。设每组 4 个输入字节为 a,b,c,d（都已被加 83），`$4` 按 2→3→4→1 的顺序做 `+g[0]`、`-g[1]`、`*g[2]`、`^g[3]` 再异或固定掩码 32/36/19/55 并 +83，得到四条约束：

  ```
  ((b + (a + g[0])) ^ 32) + 83 = t[1]
  ((c + (t[1] - g[1])) ^ 36) + 83 = t[2]
  ((d + (t[2] * g[2])) ^ 19) + 83 = t[3]
  ((a + (t[3] ^ g[3])) ^ 55) + 83 = t[0]
  ```

  20 个密文常量分成 5 组，每组 4 个未知数、4 个方程；字符空间只有可打印 ASCII（加 83 偏移后 115–209），直接四层循环爆破或 z3 都能秒解。
- **为什么可行**：wasm 是栈式字节码，浏览器运行时仍可单步、读写全局和内存；客户端的所有常量与算法都在本地，动态调试可以绕过"静态工具不支持新提案"的限制。

## 触发条件

- 目标是浏览器加载/内嵌 wasm 的 CTF 题或前端校验逻辑，能拿到页面 HTML/JS 或 `.wasm`。
- 使用 Chrome 等支持 Wasm GC/function-references 等新提案的浏览器（旧版浏览器同样会加载失败）。
- 本地 wabt/JEB 等静态工具版本不支持该模块使用的提案（wasm2c/wasm2wat 报类型错误）。
- 能通过页面输入或修改脚本触发导出函数（引用类型参数不能直接从 console 构造）。

## 利用步骤

1. 在页面源码/DevTools 中找到内嵌的十进制数组 `code`；用 CyberChef "From Decimal" 或 `bytes(code)` 还原 `.wasm`，确认魔数 `00 61 73 6d`。
2. 先试静态路径：`wasm2wat`/`wasm2c`（wabt）、JEB 的 wasm 反编译。若 `wasm2c` 报 `unexpected type form (got -0x30)`，在 wat 中检查是否有 struct/array 类型与 `(ref null $type)` 参数，判断为 GC/function-references 提案导致。
3. Chrome DevTools → Sources → 打开 wasm 模块（wat 视图），在 `init`、`array_fill`、`check` 等导出函数上下断点。
4. 构造格式合法的假 flag（如 `TetCTF{0123456789abcdefghi}`）从页面输入触发；或在 Overrides 中把 `wasm` 实例挂到 `window` 后从 console 调用页面自身的封装函数。
5. 单步执行 `$check`，记录：密文比较常量、每组的运算顺序与掩码、以及启动函数对全局 g 的异或解密过程，取解密后的真实 g。
6. 把 `$check` 的逻辑整理成每 4 字节一组的方程；用 Python 四层爆破或 z3 求解（注意所有输入字符先加 83）。
7. 拼接解出的 ASCII 得到 flag：本题为 `TetCTF{WebAss3mblyMystique}`。

## PoC

原文给出的爆破脚本（已整理为可直接运行的形式，g 为运行时解密后的真实数组）：

```python
g = [115, 82, 52, 149, 136, 67, 76, 97, 71, 90, 71, 74, 124, 104, 84, 67, 114, 127, 52, 31]
t = [38793, 584, 738, 38594, 63809, 647, 833, 63602, 47526, 494, 663, 47333,
     67041, 641, 791, 66734, 35553, 561, 673, 35306]

def solve(g, t, o):
    for a in range(32 + 83, 127 + 83):
        for b in range(32 + 83, 127 + 83):
            eq1 = ((b + (a + g[4 * o])) ^ 32) + 83
            if eq1 != t[1 + 4 * o]:
                continue
            for c in range(32 + 83, 127 + 83):
                eq2 = ((c + (eq1 - g[1 + 4 * o])) ^ 36) + 83
                if eq2 != t[2 + 4 * o]:
                    continue
                for d in range(32 + 83, 127 + 83):
                    eq3 = ((d + (eq2 * g[2 + 4 * o])) ^ 19) + 83
                    eq4 = ((a + (eq3 ^ g[3 + 4 * o])) ^ 55) + 83
                    if eq3 == t[3 + 4 * o] and eq4 == t[0 + 4 * o]:
                        return a, b, c, d
    return None

inside = ''.join(chr(x - 83) for o in range(5) for x in solve(g, t, o))
print('TetCTF{' + inside)  # inside 已含右花括号：WebAss3mblyMystique}
```

- 若用 z3，可直接把上面四条等式写成 `Int` 约束，并加 `32+83 <= x <= 126+83`，无需爆破。
- 注意爆破范围是 `32+83 .. 126+83`，因为 wasm 内每个字符先加了 83；直接按可见字符范围会漏解。

## 变体与关联

- **与通用 wasm 逆向卡的关系**：`code-analysis-reverse-wasm-browser-debug-memory-helpers` 覆盖 wabt/IDA/JEB 静态反编译 + devtools 调 wat + 注入 `viewString/search` 等内存辅助函数的通用双路径；本卡针对的是该路径失效的场景——模块使用 Wasm GC/function-references，wasm2c 直接报错，只能靠浏览器动调，且关键密钥数组是运行时异或解密的，需要额外识别。
- **内嵌 wasm 提取**：`ctf-reverse-wechat-miniprogram-embedded-wasm-extract-xor` 按 `00 61 73 6d` 魔数从二进制包中 dump 内嵌 wasm；本题是 JS 十进制数组形式，还原方式不同（CyberChef From Decimal / `bytes()`）。
- **其它 wasm 校验题**：`ctf-reverse-wasm-login-*` 系列展示了 FNV-1a/Feistel/xorshift、时间戳爆破等算法还原；本题的差异点是"工具链不支持新提案 + 运行时全局解密 + 4 元方程组"。
- **工具变体**：遇到 wasm2c 失败还可尝试更新版 wabt、`wasm-tools dump`/`wasm-tools print`、Binaryen `wasm-dis`、Ghidra wasm 加载器；若模块被混淆，可在运行时 dump 内存/全局或 hook `WebAssembly.instantiate` 导出实例。
- **其它提案触发同类报错**：reference types、SIMD、exception handling 等后 MVP 特性都可能让旧版静态工具失败，判断方法都是看类型段与函数签名。

## 检测与防御

- **客户端校验不是安全边界**：wasm 的常量、算法和运行时解密逻辑都能被 DevTools 单步提取；不要把 flag、密钥或许可判断只放在客户端，最终校验必须在服务端完成。
- **提高逆向成本而非依赖保密**：可做代码分片、常量运行时派生、wasm 混淆/自定义 VM，但这些只增加分析时间，不能阻止动态调试；涉及授权/计费的逻辑应结合服务端签名或远程证明。
- **检测可疑调试行为**（防守方视角）：前端 wasm 题/产品若需防调试，可检测 DevTools 断点、`debugger` 停顿、`WebAssembly` 导出被改写等，但浏览器环境不可信，最终仍应服务端校验。
- **CTF 出题视角**：本题用 GC/function-references 提案让 wasm2c 失效、再用运行时异或隐藏真实常量，是提高难度的有效手法；可组合内存加密、导入函数间接调用等进一步对抗静态分析。
