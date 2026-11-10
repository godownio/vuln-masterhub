---
id: web-php-rce-webshell-doccomment-string-carrier
title: 用 ReflectionClass::getDocComment 把危险代码藏在类注释里：substr 切片后交 eval 执行
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-doccomment-code-carrier
aliases:
- 注释藏马
- getDocComment 免杀
- ReflectionClass 读注释执行
- 注释读取型 webshell
tags:
- php
- webshell
- av-bypass
- obfuscation
- reflection
- doccomment
- data-carrier
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:55:55+08:00'
  notes: 已对照原文核对；ReflectionClass::getDocComment + substr(comment,8,17) + eval 与原文 PoC 一致；confidence=medium 合理（原文未给免杀效果截图）；未执行 PHP 载荷
---

## 一句话结论

把要执行的 PHP 代码写进类的 doc 注释（`/** system('whoami'); */`），运行时用 `new ReflectionClass('User')->getDocComment()` 取回整段注释，再用 `substr($comment, 8, 17)` 这类偏移切片截出注释里的代码片段，最后 `eval($f)` 执行；文件正文里没有任何危险函数调用语句，`system(...)` 只以注释文本形式存在，静态扫描若跳过或弱化注释区就会漏判。

## 原理

- **注释是运行时仍可读的数据**：PHP 的 `ReflectionClass::getDocComment()` 返回紧贴类声明上方的 `/** ... */` 原文（含注释符号本身），字符串内容完全可控、不参与编译，但可以被任意切片/拼接。
- **为什么能绕**：静态扫描器常把注释视为"非代码"而降低权重甚至跳过（否则正常注释里的大量示例代码会变成海量误报）；而本手法正好把 payload 放在注释里，代码区只留 `getDocComment` + `substr` + `eval` 三个"看起来像文档处理/动态求值"的语句。若扫描器对 `eval` 仍敏感，可把 `eval` 也换成 `$f($code)` 变量函数或 `assert`。
- **偏移量就是定位器**：`substr($comment, 8, 17)` 中 8 是跳过 `/**\n * ` 前缀后的起点、17 是 payload 长度；注释里的换行/缩进都会改变偏移，因此 payload 与偏移量必须成对生成（换模板即需重算）。
- **可执行性已验证**：注释里的 `system('whoami');` 被切出后作为字符串送进 `eval`，等价于直接写 `system('whoami');`；只是执行点在运行时而非源码字面。
- **局限**：`eval` 本身是高危结构，多数规则仍会命中；因此该手法更适合与其它隐藏手段（变量函数、异或函数名）叠加，单独使用时免杀效果有限。

## 触发条件

- 目标 PHP 允许 `eval`（或可换成 `assert`/变量函数）；
- 文件可落地并被访问（上传/写入/包含前置独立）；
- 防护以关键字/结构匹配为主，且对注释区处理不严（跳过注释、或只做浅层正则）；
- payload 长度与 `substr` 偏移匹配（模板化生成时需同步）。

## 利用步骤

1. 在任意类声明上方写 doc 注释，注释体里放待执行代码（如 `system('whoami');`），保持 `/**` 开头的典型格式。
2. 运行时取注释：`$comment = (new ReflectionClass('User'))->getDocComment();`。
3. 用 `substr` 按固定偏移截出代码段（先 `echo` 验证切片结果，确认长度与起点）。
4. 把结果交给 `eval($f)`（或 `assert($f)`、`$g($f)`）。
5. 若要提高隐蔽性：类名/方法名改为无意义名、把 `eval` 换成变量函数、注释里改用 `$` 拼接形式避开正则。

## PoC

```php
<?php
/**
 * system('whoami');
 * */
class User {}

$user = new ReflectionClass('User');
$comment = $user->getDocComment();
echo $comment;              // 调试：确认注释原文
$f = substr($comment, 8, 17);   // 截出注释里的代码片段
echo $f;                    // 调试：应为 system('whoami');
eval($f);
```

## 变体与关联

- 变体：注释载体换成 `ReflectionFunction::getDocComment()`、`ReflectionMethod::getDocComment()`，或 `php_strip_whitespace()` 之外的读文件方式（`file_get_contents(__FILE__)` + 正则提取注释）。
- 变体：把注释里的片段再异或/取反，切片后先解码再 `eval`，形成"注释 + 编码"双层。
- 变体：把 payload 放注释、把"切片偏移"放常量或配置，形成"数据/逻辑分离"。
- 关联：[[web-php-rce-webshell-obscure-callback-uintersect]]（同样把危险内容从代码区挪走，那条挪的是函数名）。
- 关联：[[web-php-rce-webshell-sqlite-query-string-function-name]]（另一类"从非代码数据读取函数名"的载体）。
- 边界：`eval` 被 `disable_functions` 禁用（`eval` 是语言结构，不能被 disable_functions 禁用，但可用 suhosin/扩展限制）或扫描器对注释区做完整 AST 化时失效；偏移量写错会截出非法 PHP 导致解析错误。

## 检测与防御

- 检测：PHP 文件中出现 `getDocComment` + `substr`/`preg_match` + `eval`/`assert` 的组合；对注释区也做敏感函数检测（至少做"注释内出现 system/exec/eval"的告警）；运行时看 `eval` 的调用来源是否为反射所得字符串。
- 防御：生产代码禁用 `eval`（代码审查层面），对上传文件做 AST 级检测并包含注释节点；`disable_functions` 覆盖执行类函数；上传目录禁解析。
